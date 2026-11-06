"""Modelled Linux adapter tests with fake processes, NOT Oracle extraction proof."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from fox import linux_forms
from fox import extractor
from fox.extractor import ExtractionError, NS, PLL_NS, digest, prepare, verify
from fox.linux_forms import LinuxOracleFormsBackend


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    # All vendor files and binary inputs here are labelled placeholders.
    home, java, scratch = (tmp_path / name for name in ('oracle', 'jdk', 'scratch'))
    for folder in [home / 'jlib', home / 'lib', home / 'bin',
                   home / 'oracle_common/modules/oracle.xdk', java / 'bin', scratch]:
        folder.mkdir(parents=True, exist_ok=True)
    for file in [java / 'bin/java', java / 'bin/javac', home / 'bin/frmf2xml',
                 home / 'jlib/frmxmltools.jar', home / 'jlib/frmjdapi.jar',
                 home / 'oracle_common/modules/oracle.xdk/xmlparserv2.jar']:
        file.write_bytes(b'FAKE_TOOL_NOT_ORACLE')
        file.chmod(0o700)
    monkeypatch.setattr(linux_forms, 'sys', SimpleNamespace(platform='linux'))
    backend = LinuxOracleFormsBackend(home, java, temp_root=scratch)
    return backend


def inputs(tmp_path, ext='fmb'):
    folder = tmp_path / 'input'
    folder.mkdir(exist_ok=True)
    source = folder / ('synthetic.' + ext)
    source.write_bytes(b'FAKE_BINARY_NOT_ORACLE')
    destination = tmp_path / ('out-' + ext)
    destination.mkdir()
    return source, destination


def forms_xml(ext='fmb'):
    kind = {'fmb': 'FormModule', 'mmb': 'MenuModule', 'olb': 'ObjectLibrary'}[ext]
    return f'<Module xmlns="{NS[1:-1]}"><{kind} Name="DEMO"/></Module>'.encode()


def fake_forms(monkeypatch, output=None):
    calls = []

    def run(args, **kwargs):
        source = Path(args[-1])
        calls.append((args, kwargs, source.read_bytes()))
        # Model observed Oracle behavior, not an invented OUTPUTDIR contract:
        # Forms2XML emits beside its input even when cwd is a different folder.
        (source.parent / (source.stem + '_' + source.suffix[1:] + '.xml')).write_bytes(
            forms_xml(source.suffix[1:]) if output is None else output)
        return SimpleNamespace(returncode=0, stdout=b'')

    monkeypatch.setattr(linux_forms.subprocess, 'run', run)
    return calls


def test_presence_is_not_native_extraction_proof(runtime):
    report = runtime.check()
    assert report['backend'] == 'oracle-forms-linux-installed-v1'
    assert report['native_conversion_tested'] is False
    assert report['formats'] == ['.fmb', '.mmb', '.olb', '.pll']
    assert 'Presence check only' in report['note']


@pytest.mark.parametrize('ext', ['fmb', 'mmb', 'olb'])
@pytest.mark.parametrize('wrapper', [False, True])
@pytest.mark.parametrize('dump_mode', ['OVERRIDDEN', 'ALL'])
def test_modelled_linux_commands_and_private_environment(runtime, tmp_path, monkeypatch, ext, wrapper, dump_mode):
    runtime.dump_mode = dump_mode
    if wrapper:
        runtime.frmf2xml = runtime.home / 'bin/frmf2xml'
    source, destination = inputs(tmp_path, ext)
    for name in ['JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'LD_PRELOAD',
                 'TNS_ADMIN', 'TWO_TASK', 'DISPLAY', 'HTTPS_PROXY', 'CLASSPATH', 'FORMS_API_TK_BYPASS']:
        monkeypatch.setenv(name, 'SENSITIVE_VALUE_DO_NOT_INHERIT')
    calls = fake_forms(monkeypatch)
    original = source.read_bytes()
    output = runtime.extract(source, destination)
    assert output.read_bytes() == forms_xml(ext)
    assert source.read_bytes() == original
    args, kwargs, staged_bytes = calls[0]
    staged = Path(args[-1])
    assert staged_bytes == original
    assert staged != source and staged.name == source.name
    assert staged.is_relative_to(runtime.temp_root)
    if wrapper:
        assert args[0] == str(runtime.frmf2xml)
    else:
        assert args[:4] == [str(runtime.java), '-cp', ':'.join(map(str, runtime.jars)),
                            'oracle.forms.util.xmltools.Forms2XML']
    assert args[-4:] == ['DUMP=' + dump_mode, 'USE_PROPERTY_IDS=NO', 'OVERWRITE=NO', str(staged)]
    assert not any(arg.startswith('OUTPUT') for arg in args)
    assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['shell'] is False
    assert kwargs['timeout'] == 120 and kwargs['cwd'] != destination
    env = kwargs['env']
    assert 'SENSITIVE_VALUE' not in json.dumps(env)
    assert env['JAVA_HOME'] == str(runtime.java_home)
    assert env['LD_LIBRARY_PATH'] == str(runtime.home / 'lib')
    assert env['FORMS_PATH'] == env['ORACLE_PATH'] == str(source.parent)
    assert env['FORMS_API_TK_BYPASS'] == 'TRUE' and 'DISPLAY' not in env
    assert env['HOME'] == env['TMPDIR']
    assert kwargs['cwd'] == Path(env['HOME'])
    assert staged.parent == Path(env['HOME']) / 'sources'
    assert not (source.parent / output.name).exists()
    assert not Path(env['HOME']).exists()
    assert not list(runtime.temp_root.iterdir())


@pytest.mark.parametrize('dump_mode', [None, True, '', 'all', 'INVALID', 'ALL --connect=unsafe'])
def test_dump_mode_configuration_is_bounded(runtime, dump_mode):
    with pytest.raises(ExtractionError, match='dump mode'):
        LinuxOracleFormsBackend(runtime.home, runtime.java_home, dump_mode=dump_mode)


def test_all_dump_does_not_silently_apply_to_pll(runtime, tmp_path, monkeypatch):
    runtime.dump_mode = 'ALL'
    assert runtime.check()['formats'] == ['.fmb', '.mmb', '.olb']
    assert runtime.check()['dump_mode'] == 'ALL'
    source, destination = inputs(tmp_path, 'pll')
    monkeypatch.setattr(linux_forms.subprocess, 'run', lambda *a, **k: pytest.fail('must not invoke tool'))
    with pytest.raises(ExtractionError, match='not PLL'):
        runtime.extract(source, destination)


def test_explicit_paths_validated_not_guessed(runtime, tmp_path):
    jars = [tmp_path / (name + '.jar') for name in ('xmltools', 'jdapi', 'xdk')]
    for jar in jars:
        jar.write_bytes(b'FAKE_CONFIGURED_JAR')
    other = tmp_path / 'native-libs'
    other.mkdir()
    configured = LinuxOracleFormsBackend(runtime.home, runtime.java_home,
        jar_paths=jars, library_paths=[other, runtime.home / 'lib'], temp_root=runtime.temp_root)
    assert configured.jars == jars and configured.check()['tool_files_present']
    jars[0].unlink()
    with pytest.raises(ExtractionError, match='missing or unreadable'):
        configured.check()


def test_missing_javac_blocks_pll_not_forms(runtime, tmp_path):
    runtime.javac.unlink()
    assert runtime.check()['formats'] == ['.fmb', '.mmb', '.olb']
    assert '.pll' in runtime.check()['blocked_formats']
    source, destination = inputs(tmp_path, 'pll')
    with pytest.raises(ExtractionError, match='JDK compiler'):
        runtime.extract(source, destination)
    assert not list(runtime.temp_root.iterdir())


def test_modelled_pll_reuses_helper_and_integrity_validation(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path, 'pll')
    text = 'PROCEDURE HELLO IS BEGIN NULL; END;'
    raw = (f'<Module xmlns="{PLL_NS[1:-1]}" Format="FOX-JDAPI-LIBRARY-1" DatabaseConnected="false">'
           f'<LibraryModule Name="DEMO" ProgramUnitCount="1" AttachedLibraryCount="0">'
           f'<ProgramUnit Name="HELLO" ProgramUnitType="1" TextSHA256="{digest(text.encode())}">'
           f'<ProgramUnitText>{text}</ProgramUnitText></ProgramUnit></LibraryModule></Module>').encode()
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == str(runtime.java):
            assert Path(args[-2]).read_bytes() == source.read_bytes()
            Path(args[-1]).write_bytes(raw)
        return SimpleNamespace(returncode=0, stdout=b'')

    monkeypatch.setattr(linux_forms.subprocess, 'run', run)
    output = runtime.extract(source, destination)
    assert output.read_bytes() == raw
    compile_args, _ = calls[0]
    assert compile_args[:5] == [str(runtime.javac), '-encoding', 'UTF-8', '--release', '17']
    assert compile_args[-1] == str(runtime.pll_helper)
    assert calls[1][0][3] == 'FoxPllExtract'
    staged, generated = map(Path, calls[1][0][-2:])
    assert staged.name == source.name and staged != source
    assert generated.name == output.name and generated != output
    assert staged.parent == generated.parent
    assert staged.is_relative_to(runtime.temp_root)
    assert not (source.parent / output.name).exists()
    assert not list(runtime.temp_root.iterdir())


@pytest.mark.parametrize('mode', ['timeout', 'nonzero', 'warning', 'exception', 'frm', 'oserror'])
def test_failures_never_emit_native_diagnostics(runtime, tmp_path, monkeypatch, capsys, mode):
    source, destination = inputs(tmp_path)
    secret = b'PRIVATE_SOURCE_PASSWORD=do-not-display'

    def run(args, **kwargs):
        staged = Path(args[-1])
        (staged.parent / 'synthetic_fmb.xml').write_bytes(forms_xml())
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(args, 1, output=secret)
        if mode == 'oserror':
            raise OSError(secret.decode())
        return SimpleNamespace(returncode=int(mode == 'nonzero'),
                               stdout=secret + b' ' + {'warning': b'warning', 'exception': b'Exception',
                                                     'frm': b'FRM-12345'}.get(mode, b''))

    monkeypatch.setattr(linux_forms.subprocess, 'run', run)
    with pytest.raises(ExtractionError) as error:
        runtime.extract(source, destination)
    assert secret.decode() not in str(error.value)
    assert capsys.readouterr() == ('', '')
    assert not list(runtime.temp_root.iterdir())
    assert not list(destination.iterdir())
    assert list(source.parent.iterdir()) == [source]


@pytest.mark.parametrize('payload', [b'<invalid', b'<Module/>', b'',
    b'<!DOCTYPE a [<!ENTITY x "sensitive">]><a>&x;</a>',
    b'x' * (5 * 1024 * 1024 + 1), forms_xml('mmb')],
    ids=['malformed', 'no-module', 'empty', 'entity', 'oversized', 'wrong-kind'])
def test_bad_or_wrong_module_output_blocked(runtime, tmp_path, monkeypatch, payload):
    source, destination = inputs(tmp_path)
    fake_forms(monkeypatch, payload)
    with pytest.raises(ExtractionError):
        runtime.extract(source, destination)
    assert not list(destination.iterdir())
    assert list(source.parent.iterdir()) == [source]
    assert not list(runtime.temp_root.iterdir())


@pytest.mark.parametrize('value', ['relative/path', '/tmp/../unsafe', '/tmp/bad\npath', '/tmp/bad:path', '/tmp/bad\x00path'])
def test_malformed_configuration_is_safe(value, tmp_path):
    with pytest.raises(ExtractionError) as error:
        LinuxOracleFormsBackend(value, tmp_path)
    assert value not in str(error.value)


@pytest.mark.parametrize('value', [True, 0, -1, 601, 1.5, '120'])
def test_timeout_configuration_bounded(runtime, value):
    with pytest.raises(ExtractionError, match='timeout'):
        LinuxOracleFormsBackend(runtime.home, runtime.java_home, timeout=value)


@pytest.mark.parametrize('kind', ['source', 'output', 'tool', 'home'])
def test_symlinks_rejected_before_process(runtime, tmp_path, monkeypatch, kind):
    source, destination = inputs(tmp_path)
    target = {'source': source, 'output': destination, 'tool': runtime.java, 'home': runtime.home}[kind]
    link = tmp_path / ('link-' + target.name)
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip('Host does not permit symlink creation; run on configured Linux host too.')
    monkeypatch.setattr(linux_forms.subprocess, 'run', lambda *a, **k: pytest.fail('must not invoke tool'))
    with pytest.raises(ExtractionError):
        if kind == 'source':
            runtime.extract(link, destination)
        elif kind == 'output':
            runtime.extract(source, link)
        elif kind == 'tool':
            runtime.java = link
            runtime.extract(source, destination)
        else:
            LinuxOracleFormsBackend(link, runtime.java_home)


def test_nonempty_destination_never_overwritten(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    original = destination / 'synthetic_fmb.xml'
    original.write_bytes(b'preserve-me')
    monkeypatch.setattr(linux_forms.subprocess, 'run', lambda *a, **k: pytest.fail('must not invoke tool'))
    with pytest.raises(ExtractionError, match='empty dedicated'):
        runtime.extract(source, destination)
    assert original.read_bytes() == b'preserve-me'


def test_original_mutation_blocks_result(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    calls = fake_forms(monkeypatch)
    wrapped = linux_forms.subprocess.run

    def changed(*args, **kwargs):
        result = wrapped(*args, **kwargs)
        source.write_bytes(b'changed-by-fake-process')
        return result

    monkeypatch.setattr(linux_forms.subprocess, 'run', changed)
    with pytest.raises(ExtractionError, match='Source changed'):
        runtime.extract(source, destination)
    assert len(calls) == 1
    assert not list(destination.iterdir())


def test_staged_mutation_blocks_result_without_changing_original(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    original = source.read_bytes()
    fake_forms(monkeypatch)
    wrapped = linux_forms.subprocess.run

    def changed(args, **kwargs):
        result = wrapped(args, **kwargs)
        Path(args[-1]).write_bytes(b'changed-staged-copy')
        return result

    monkeypatch.setattr(linux_forms.subprocess, 'run', changed)
    with pytest.raises(ExtractionError, match='Staged source changed'):
        runtime.extract(source, destination)
    assert source.read_bytes() == original
    assert not list(destination.iterdir())
    assert not list(runtime.temp_root.iterdir())


@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_generated_link_is_never_published(runtime, tmp_path, monkeypatch, kind):
    source, destination = inputs(tmp_path)
    external = tmp_path / 'private-target.xml'
    external.write_bytes(forms_xml())
    original = source.read_bytes()

    def linked(args, **kwargs):
        generated = Path(args[-1]).with_name('synthetic_fmb.xml')
        try:
            if kind == 'symlink':
                generated.symlink_to(external)
            else:
                os.link(external, generated)
        except OSError:
            pytest.skip('Host cannot create this link; run the case on Linux too.')
        return SimpleNamespace(returncode=0, stdout=b'')

    monkeypatch.setattr(linux_forms.subprocess, 'run', linked)
    with pytest.raises(ExtractionError):
        runtime.extract(source, destination)
    assert source.read_bytes() == original
    assert external.read_bytes() == forms_xml()
    assert not list(destination.iterdir())
    assert not list(runtime.temp_root.iterdir())


def test_modelled_generated_symlink_metadata_blocks_before_publication(runtime, tmp_path, monkeypatch):
    """Exercise the link guard even on Windows without symlink privileges."""
    source, destination = inputs(tmp_path)
    fake_forms(monkeypatch)
    wrapped = linux_forms.subprocess.run
    actual_lstat = Path.lstat

    def linked_metadata(args, **kwargs):
        result = wrapped(args, **kwargs)
        generated = Path(args[-1]).with_name('synthetic_fmb.xml')

        def lstat(path, *stat_args, **stat_kwargs):
            if path == generated:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777,
                                       st_nlink=1, st_file_attributes=0)
            return actual_lstat(path, *stat_args, **stat_kwargs)

        monkeypatch.setattr(Path, 'lstat', lstat)
        return result

    monkeypatch.setattr(linux_forms.subprocess, 'run', linked_metadata)
    with pytest.raises(ExtractionError):
        runtime.extract(source, destination)
    assert not list(destination.iterdir())
    assert list(source.parent.iterdir()) == [source]
    assert not list(runtime.temp_root.iterdir())


def test_missing_beside_input_output_does_not_use_cwd_artifact(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)

    def wrong_location(args, **kwargs):
        (kwargs['cwd'] / 'synthetic_fmb.xml').write_bytes(forms_xml())
        return SimpleNamespace(returncode=0, stdout=b'')

    monkeypatch.setattr(linux_forms.subprocess, 'run', wrong_location)
    with pytest.raises(ExtractionError, match='missing'):
        runtime.extract(source, destination)
    assert not list(destination.iterdir())
    assert list(source.parent.iterdir()) == [source]


def test_original_adjacent_xml_and_dependency_lookup_are_preserved(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    adjacent = source.with_name('synthetic_fmb.xml')
    adjacent.write_bytes(b'PRESERVE_ORIGINAL_ADJACENT_XML')
    calls = fake_forms(monkeypatch)
    output = runtime.extract(source, destination)
    assert output.read_bytes() == forms_xml()
    assert adjacent.read_bytes() == b'PRESERVE_ORIGINAL_ADJACENT_XML'
    assert calls[0][1]['env']['FORMS_PATH'] == str(source.parent)
    assert calls[0][0][-1] != str(source)


def test_destination_changed_during_tool_run_is_not_overwritten(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    fake_forms(monkeypatch)
    wrapped = linux_forms.subprocess.run
    existing = destination / 'synthetic_fmb.xml'

    def changed(args, **kwargs):
        result = wrapped(args, **kwargs)
        existing.write_bytes(b'PRESERVE_NEW_DESTINATION_ARTIFACT')
        return result

    monkeypatch.setattr(linux_forms.subprocess, 'run', changed)
    with pytest.raises(ExtractionError, match='destination changed'):
        runtime.extract(source, destination)
    assert existing.read_bytes() == b'PRESERVE_NEW_DESTINATION_ARTIFACT'
    assert not list(runtime.temp_root.iterdir())


def test_additional_native_assets_block_instead_of_silently_disappearing(runtime, tmp_path, monkeypatch):
    source, destination = inputs(tmp_path)
    fake_forms(monkeypatch)
    wrapped = linux_forms.subprocess.run

    def sidecar(args, **kwargs):
        result = wrapped(args, **kwargs)
        Path(args[-1]).with_name('image.png').write_bytes(b'FAKE_IMAGE_ASSET')
        return result

    monkeypatch.setattr(linux_forms.subprocess, 'run', sidecar)
    with pytest.raises(ExtractionError, match='additional artifacts'):
        runtime.extract(source, destination)
    assert not list(destination.iterdir())
    assert list(source.parent.iterdir()) == [source]


def test_prepare_reuses_stable_hashes_and_keeps_review_gate(runtime, tmp_path, monkeypatch):
    source, _ = inputs(tmp_path)
    fake_forms(monkeypatch)
    original = source.read_bytes()
    jobs = [prepare(source.parent, tmp_path / 'jobs', runtime, job_id='modelled-' + str(i)) for i in range(2)]
    manifests = [json.loads((job / 'manifest.json').read_text()) for job in jobs]
    assert manifests[0]['source_manifest_hash'] == manifests[1]['source_manifest_hash']
    assert manifests[0]['readable_source_hash'] == manifests[1]['readable_source_hash']
    assert manifests[0]['inputs'][0]['sha256'] == digest(original)
    assert manifests[0]['files'][0]['backend'] == runtime.name
    assert verify(jobs[0])['approved_for_upload'] is False
    assert source.read_bytes() == original


@pytest.mark.parametrize('platform', ['win32', 'darwin', 'freebsd14', 'sunos5'])
def test_nonlinux_host_blocked(runtime, monkeypatch, platform):
    monkeypatch.setattr(linux_forms, 'sys', SimpleNamespace(platform=platform))
    with pytest.raises(ExtractionError, match='Linux'):
        runtime.check()


def call_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, 'argv', ['fox.extractor', *map(str, args)])
    return extractor.main()


@pytest.mark.parametrize('backend', [None, 'readable'])
def test_cli_readable_does_not_import_linux_or_construct_native(monkeypatch, capsys, backend):
    import builtins
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != 'linux_forms', 'Readable CLI must not import the native Linux adapter.'
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', guarded_import)
    monkeypatch.setattr(extractor, 'OracleFormsBackend', lambda *a, **k: pytest.fail('no native backend'))
    flags = ['--backend', backend] if backend else []
    assert call_cli(monkeypatch, 'check', *flags) == 0
    assert json.loads(capsys.readouterr().out)['backend'] == 'readable-v1'


@pytest.mark.parametrize('backend', [None, 'windows'])
def test_cli_preserves_implicit_and_explicit_windows_selection(monkeypatch, capsys, tmp_path, backend):
    calls = []

    def construct(home, java):
        calls.append((home, java))
        return SimpleNamespace(check=lambda: {'backend': 'FAKE_WINDOWS_CHECK_ONLY',
                                              'native_conversion_tested': False})

    monkeypatch.setattr(extractor, 'OracleFormsBackend', construct)
    flags = ['--backend', backend] if backend else []
    assert call_cli(monkeypatch, 'check', *flags, '--oracle-home', tmp_path / 'oracle',
                    '--java', tmp_path / 'java.exe') == 0
    assert calls == [(tmp_path / 'oracle', tmp_path / 'java.exe')]
    assert json.loads(capsys.readouterr().out)['native_conversion_tested'] is False


def test_cli_linux_uses_java_home_directory_and_presence_only_check(runtime, monkeypatch, capsys):
    calls = []

    def construct(home, java_home):
        calls.append((home, java_home))
        return runtime

    monkeypatch.setattr(linux_forms, 'LinuxOracleFormsBackend', construct)
    monkeypatch.setattr(extractor, 'OracleFormsBackend', lambda *a: pytest.fail('Windows must not be selected'))
    assert call_cli(monkeypatch, 'check', '--backend', 'linux', '--oracle-home', runtime.home,
                    '--java-home', runtime.java_home) == 0
    assert calls == [(runtime.home, runtime.java_home)]
    report = json.loads(capsys.readouterr().out)
    assert report['backend'] == runtime.name and report['native_conversion_tested'] is False


@pytest.mark.parametrize('flags', [
    ['--backend', 'linux'],
    ['--backend', 'linux', '--oracle-home', 'unused'],
    ['--backend', 'linux', '--java-home', 'unused'],
    ['--backend', 'linux', '--oracle-home', 'unused', '--java', 'unused'],
    ['--backend', 'windows'],
    ['--backend', 'windows', '--oracle-home', 'unused', '--java-home', 'unused'],
    ['--backend', 'readable', '--oracle-home', 'unused'],
    ['--backend', 'readable', '--java', 'unused'],
    ['--backend', 'readable', '--java-home', 'unused'],
    ['--java-home', 'unused'],
])
def test_cli_rejects_incomplete_or_conflicting_explicit_runtime_options(monkeypatch, capsys, flags):
    monkeypatch.setattr(linux_forms, 'LinuxOracleFormsBackend', lambda *a: pytest.fail('invalid arguments'))
    monkeypatch.setattr(extractor, 'OracleFormsBackend', lambda *a: pytest.fail('invalid arguments'))
    with pytest.raises(SystemExit) as error:
        call_cli(monkeypatch, 'check', *flags)
    assert error.value.code == 2
    assert 'error:' in capsys.readouterr().err


def test_cli_java_executable_is_not_a_linux_java_home(runtime, monkeypatch, capsys):
    assert call_cli(monkeypatch, 'check', '--backend', 'linux', '--oracle-home', runtime.home,
                    '--java-home', runtime.java) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'BLOCKED'
    assert 'directory' in report['reason']


def test_cli_readable_verify_rejects_conflicting_runtime_flags(monkeypatch, capsys):
    with pytest.raises(SystemExit) as error:
        call_cli(monkeypatch, 'verify', '--backend', 'readable', '--oracle-home', 'unused')
    assert error.value.code == 2
    assert 'does not accept Oracle runtime options' in capsys.readouterr().err


def test_cli_linux_rejects_mac_even_with_configured_tool_files(runtime, monkeypatch, capsys):
    monkeypatch.setattr(linux_forms, 'sys', SimpleNamespace(platform='darwin'))
    assert call_cli(monkeypatch, 'check', '--backend', 'linux', '--oracle-home', runtime.home,
                    '--java-home', runtime.java_home) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'BLOCKED' and 'Linux' in report['reason']


def test_cli_verify_never_constructs_native_runtime(tmp_path, monkeypatch, capsys):
    source = tmp_path / 'readable-source'
    source.mkdir()
    (source / 'demo.xml').write_bytes(forms_xml())
    job = prepare(source, tmp_path / 'jobs', job_id='portable-verify')
    monkeypatch.setattr(linux_forms, 'LinuxOracleFormsBackend', lambda *a: pytest.fail('verify is portable'))
    monkeypatch.setattr(extractor, 'OracleFormsBackend', lambda *a: pytest.fail('verify is portable'))
    assert call_cli(monkeypatch, 'verify', '--job', job, '--backend', 'linux') == 0
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'VERIFIED_REVIEW_REQUIRED'
    assert report['approved_for_upload'] is False


@pytest.mark.parametrize('sensitive', [False, True])
def test_cli_prepare_linux_preserves_format_hash_and_privacy_gate(runtime, tmp_path, monkeypatch, capsys, sensitive):
    source, _ = inputs(tmp_path)
    original = source.read_bytes()
    payload = (b'<Module xmlns="http://xmlns.oracle.com/Forms"><FormModule Name="DEMO">'
               b'<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="INSERT INTO demo VALUES (1);"/>'
               b'</FormModule></Module>') if sensitive else forms_xml()
    fake_forms(monkeypatch, payload)
    monkeypatch.setattr(linux_forms, 'LinuxOracleFormsBackend', lambda *a: runtime)
    code = call_cli(monkeypatch, 'prepare', '--backend', 'linux', '--oracle-home', runtime.home,
                    '--java-home', runtime.java_home, '--source', source.parent,
                    '--output', tmp_path / 'jobs', '--job-id', 'modelled-cli')
    report = json.loads(capsys.readouterr().out)
    assert source.read_bytes() == original
    if sensitive:
        assert code == 1 and report['status'] == 'BLOCKED'
        assert not (tmp_path / 'jobs/modelled-cli/ready').exists()
    else:
        assert code == 0 and report['status'] == 'VERIFIED_REVIEW_REQUIRED'
        assert report['approved_for_upload'] is False
        manifest = json.loads((tmp_path / 'jobs/modelled-cli/manifest.json').read_text())
        assert manifest['schema_version'] == 1
        assert manifest['inputs'][0]['sha256'] == digest(original)
        assert manifest['files'][0]['sha256'] == digest(payload)
