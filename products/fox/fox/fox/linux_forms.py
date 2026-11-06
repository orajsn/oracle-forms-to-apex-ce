"""Configured Linux Forms2XML/JDAPI adapter; no installer, DB or model calls.

Tool presence is not compatibility proof. Configure paths from the actual
installation and prove representative extraction separately. This implements
extractor.Backend, so prepare/assess retain original and readable SHA-256 checks.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from defusedxml import ElementTree as ET

from .extractor import (BINARY, MAX_RAW_BYTES, MODULE_TYPES, NS, ExtractionError,
                        OracleFormsBackend, _output_name, assert_local_path,
                        digest, safe_name, validate_pll_xml)

MAX_READABLE_BYTES = 5 * 1024 * 1024


def _path(value) -> Path:
    """Reject ambiguous paths before resolving could conceal a link."""
    try:
        path = Path(value)
        if (not path.is_absolute() or '..' in path.parts
                or any(c in str(path) for c in ('\x00', '\n', '\r', ':'))):
            # A drive colon is expected only in Windows modelled unit tests.
            if not (os.name == 'nt' and path.is_absolute() and '..' not in path.parts
                    and ':' not in str(path)[2:]
                    and not any(c in str(path) for c in ('\x00', '\n', '\r'))):
                raise ValueError()
        return assert_local_path(path)
    except (ValueError, OSError, TypeError):
        raise ExtractionError('Use absolute, local, unlinked Linux runtime and job paths.') from None


def _read_bounded(path: Path, limit: int) -> bytes:
    path = _path(path)
    if not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ExtractionError('Oracle source or readable artifact is missing, empty or exceeds its bound.')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit or len(raw) != path.stat().st_size:
        raise ExtractionError('Oracle source or readable artifact changed while reading.')
    return raw


class LinuxOracleFormsBackend(OracleFormsBackend):
    """Reuse FOX's readable artifact/PLL helper contract on a configured Linux host.

    Optional jar_paths must be (Forms2XML, JDAPI, XML parser) in that order.
    Defaults are candidates, not a claim about an uninspected Oracle Home.
    frmf2xml, when explicitly supplied, replaces the Java Forms2XML invocation.
    No command accepts database credentials; inherited environment is discarded.
    """
    name = 'oracle-forms-linux-installed-v1'

    def __init__(self, home: Path, java_home: Path, *, jar_paths=None,
                 library_paths=None, frmf2xml: Path | None = None,
                 timeout: int = 120, temp_root: Path | None = None,
                 dump_mode: str = 'OVERRIDDEN'):
        if type(dump_mode) is not str or dump_mode not in {'OVERRIDDEN', 'ALL'}:
            raise ExtractionError('Forms dump mode must be OVERRIDDEN or ALL.')
        self.dump_mode = dump_mode
        if type(timeout) is not int or not 1 <= timeout <= 600:
            raise ExtractionError('Oracle extraction timeout must be 1 to 600 seconds.')
        self.home, self.java_home = _path(home), _path(java_home)
        super().__init__(self.home, self.java_home / 'bin/java', timeout)
        self.javac = self.java_home / 'bin/javac'
        if jar_paths is not None:
            self.jars = [_path(p) for p in jar_paths]
        if len(self.jars) != 3:
            raise ExtractionError('Configure Forms2XML, JDAPI and XML parser jars in that order.')
        self.library_paths = [_path(p) for p in
                              (library_paths if library_paths is not None else [self.home / 'lib'])]
        if not self.library_paths:
            raise ExtractionError('Configure the installed Oracle native library directories.')
        self.frmf2xml = _path(frmf2xml) if frmf2xml is not None else None
        self.temp_root = _path(temp_root) if temp_root is not None else _path(tempfile.gettempdir())

    def check(self) -> dict:
        if sys.platform != 'linux':
            raise ExtractionError('This adapter requires a configured Linux Oracle Forms host.')
        for folder in [self.home, self.java_home, self.temp_root, *self.library_paths]:
            if not _path(folder).is_dir():
                raise ExtractionError('A configured Oracle, Java, library or temporary directory is missing.')
        for tool in [self.java, *self.jars, *([self.frmf2xml] if self.frmf2xml else [])]:
            if not _path(tool).is_file() or not os.access(tool, os.R_OK):
                raise ExtractionError('Configured Oracle Forms or Java tool files are missing or unreadable.')
        if not os.access(self.java, os.X_OK) or (self.frmf2xml and not os.access(self.frmf2xml, os.X_OK)):
            raise ExtractionError('Configured Oracle Forms or Java executable is not executable.')
        compiler = _path(self.javac).is_file() and os.access(self.javac, os.X_OK)
        pll_supported = compiler and self.dump_mode == 'OVERRIDDEN'
        return {'backend': self.name, 'tool_files_present': True, 'dump_mode': self.dump_mode,
                'native_conversion_tested': False,
                'formats': sorted(BINARY if pll_supported else MODULE_TYPES),
                'pll_output': 'FOX JDAPI library XML; not Oracle PLD or Forms2XML schema',
                'blocked_formats': {} if pll_supported else {'.pll':
                    'ALL dumps apply to Forms2XML modules, not PLL.' if self.dump_mode == 'ALL' else
                    'Installed JDK compiler required for the JDAPI helper.'},
                'note': 'Presence check only; run representative extraction to prove compatibility.'}

    def _run(self, args, cwd, forms_path, private):
        # Never inherit connection strings, LD_PRELOAD, JAVA_TOOL_OPTIONS,
        # classpath, proxy settings, remote Forms paths or an operator HOME.
        env = {'ORACLE_HOME': str(self.home), 'JAVA_HOME': str(self.java_home),
               'FORMS_PATH': str(forms_path), 'ORACLE_PATH': str(forms_path),
               'LD_LIBRARY_PATH': ':'.join(map(str, self.library_paths)),
               'PATH': ':'.join(map(str, [self.home / 'bin', self.java_home / 'bin'])) + ':/usr/bin:/bin',
               'HOME': str(private), 'TMPDIR': str(private),
               # Oracle Forms 14.1.2 documented JDAPI toolkit-free initialization.
               # Do not inherit DISPLAY, launch Xvfb, or source a shell profile.
               'FORMS_API_TK_BYPASS': 'TRUE',
               'NLS_LANG': 'AMERICAN_AMERICA.AL32UTF8', 'LANG': 'C.UTF-8'}
        try:
            result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=self.timeout, shell=False)
        except subprocess.TimeoutExpired:
            raise ExtractionError('Oracle extraction timed out; no package released.') from None
        except OSError:
            raise ExtractionError('Oracle tool could not start. Check Linux runtime prerequisites.') from None
        # Native diagnostics can contain source/secrets. Never persist or echo.
        if result.returncode or re.search(rb'(?i)\b(error|exception|warning)\b|FRM-\d+', result.stdout):
            raise ExtractionError('Oracle extraction reported an error or warning; inspect the module in Forms Builder.')

    def run(self, args: list[str], cwd: Path, forms_path: Path) -> None:
        """Tool runner for explicit operator-controlled roundtrip checks."""
        self.check()
        cwd, forms_path = _path(cwd), _path(forms_path)
        with tempfile.TemporaryDirectory(prefix='fox-linux-forms-', dir=self.temp_root) as private:
            self._run(args, cwd, forms_path, Path(private))

    def extract(self, source: Path, destination: Path) -> Path:
        source, destination = _path(source), _path(destination)
        safe_name(source.name)
        ext = source.suffix.lower()
        if ext not in BINARY:
            raise ExtractionError('Linux native extraction accepts FMB, MMB, OLB or PLL only.')
        if ext == '.pll' and self.dump_mode != 'OVERRIDDEN':
            raise ExtractionError('ALL dumps apply to Forms2XML modules, not PLL.')
        output = destination / _output_name(source.name)
        self.check()
        if (not source.is_file() or not 0 < source.stat().st_size <= MAX_RAW_BYTES
                or not destination.is_dir() or any(destination.iterdir())):
            raise ExtractionError('Use a bounded source and an empty dedicated extraction directory.')
        original = _read_bounded(source, MAX_RAW_BYTES)
        before = digest(original)
        with tempfile.TemporaryDirectory(prefix='fox-linux-forms-', dir=self.temp_root) as private_name:
            private = Path(private_name)
            # Forms2XML writes beside its input, not necessarily in cwd. Never
            # give Oracle the caller's original as its conversion target.
            staging = private / 'sources'
            staging.mkdir()
            staged = staging / source.name
            with staged.open('xb') as stream:
                stream.write(original)
            generated = staging / output.name
            if ext == '.pll':
                if not self.javac.is_file() or not os.access(self.javac, os.X_OK) or not _path(self.pll_helper).is_file():
                    raise ExtractionError('PLL extraction requires the installed JDK compiler and FOX JDAPI helper.')
                self._run([str(self.javac), '-encoding', 'UTF-8', '--release', '17',
                           '-cp', str(self.jars[1]), '-d', str(private), str(self.pll_helper)], private, source.parent, private)
                self._run([str(self.java), '-cp', str(private) + ':' + str(self.jars[1]),
                           'FoxPllExtract', str(staged), str(generated)], private, source.parent, private)
            else:
                prefix = ([str(self.frmf2xml)] if self.frmf2xml else
                          [str(self.java), '-cp', ':'.join(map(str, self.jars)),
                           'oracle.forms.util.xmltools.Forms2XML'])
                self._run([*prefix, 'DUMP=' + self.dump_mode, 'USE_PROPERTY_IDS=NO',
                           'OVERWRITE=NO', str(staged)], private, source.parent, private)
            if digest(_read_bounded(source, MAX_RAW_BYTES)) != before:
                raise ExtractionError('Source changed during extraction; no package released.')
            if digest(_read_bounded(staged, MAX_RAW_BYTES)) != before:
                raise ExtractionError('Staged source changed during extraction; no package released.')
            if any(path not in (staged, generated) for path in staging.iterdir()):
                raise ExtractionError('Oracle produced additional artifacts; review the module before preparing a package.')
            raw = _read_bounded(generated, MAX_READABLE_BYTES)
            if ext == '.pll':
                validate_pll_xml(raw)
            else:
                try:
                    root = ET.fromstring(raw)
                    if root.tag != NS + 'Module' or len(root) != 1 or root[0].tag != NS + MODULE_TYPES[ext]:
                        raise ValueError()
                except Exception:
                    raise ExtractionError('Oracle output did not contain the expected Forms module type.') from None
            readable_hash = digest(raw)
            # Recheck after native execution/validation; publish exact validated
            # bytes exclusively, never move an untrusted generated path.
            if digest(_read_bounded(source, MAX_RAW_BYTES)) != before:
                raise ExtractionError('Source changed during extraction; no package released.')
            destination = _path(destination)
            if not destination.is_dir() or any(destination.iterdir()):
                raise ExtractionError('Extraction destination changed; no package released.')
            with output.open('xb') as stream:
                stream.write(raw)
            if digest(_read_bounded(output, MAX_READABLE_BYTES)) != readable_hash:
                raise ExtractionError('Readable output changed during publication; no package released.')
        return output
