"""Batch SQLcl never inherits an interactive or invalid Windows console handle."""
from pathlib import Path
import subprocess

from forms2apex import sqlcl


def test_batch_script_uses_empty_input_pipe_and_removes_script(tmp_path, monkeypatch):
    executable = tmp_path / 'sql.exe'
    executable.write_bytes(b'test executable marker')
    observed = {}

    def run(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        script = Path(argv[-1][1:])
        observed['script'] = script
        observed['body'] = script.read_text()
        assert kwargs['input'] == ''
        assert kwargs['text'] is True
        assert 'stdin' not in kwargs
        return subprocess.CompletedProcess(argv, 0, 'Validation successful', '')

    monkeypatch.setattr(sqlcl.subprocess, 'run', run)
    result = sqlcl._run_script(executable, ['-S', '/nolog'], ['apex validate -input .'], tmp_path)
    assert result.returncode == 0
    assert observed['argv'][1:4] == ['-nohistory', '-S', '/nolog']
    assert 'apex validate -input .' in observed['body']
    assert not observed['script'].exists()
