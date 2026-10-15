import os
import sys
import pytest
from app.postprocessing import run_postprocessor


def test_adapter_preserves_global_cwd_and_handles_spaced_filenames(tmp_path):
    script = tmp_path / 'processor.py'
    script.write_text('import pathlib,sys\npathlib.Path("output.txt").write_text(pathlib.Path(sys.argv[1]).read_text())\n')
    (tmp_path / 'sample with spaces.txt').write_text('benign development sample')
    previous = os.getcwd()
    run_postprocessor(f'{sys.executable} {script} {{FILENAME}}', 'sample with spaces.txt', tmp_path)
    assert os.getcwd() == previous
    assert (tmp_path / 'output.txt').read_text() == 'benign development sample'
    with pytest.raises(ValueError):
        run_postprocessor('', 'sample with spaces.txt', tmp_path, image='unversioned')
