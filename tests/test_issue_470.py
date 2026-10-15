import os
import sys
import pytest
from app.postprocessing import run_postprocessor


def test_adapter_preserves_global_cwd_and_handles_spaced_filenames(tmp_path):
    script = tmp_path / "processor.py"
    script.write_text(
        'import pathlib,sys\npathlib.Path("output.txt").write_text(pathlib.Path(sys.argv[1]).read_text())\n'
    )
    (tmp_path / "sample with spaces.txt").write_text("benign development sample")
    previous = os.getcwd()
    run_postprocessor(
        f"{sys.executable} {script} {{FILENAME}}", "sample with spaces.txt", tmp_path
    )
    assert os.getcwd() == previous
    assert (tmp_path / "output.txt").read_text() == "benign development sample"
    with pytest.raises(ValueError):
        run_postprocessor("", "sample with spaces.txt", tmp_path, image="unversioned")


def test_optional_dfi_skips_legacy_wrapper_without_disabling_other_processors():
    from types import SimpleNamespace
    from app.postprocessing import select_postprocessors

    settings = [
        SimpleNamespace(key=key, value=value)
        for key, value in [
            ("POSTPROCESSOR_DFI", "/usr/local/bin/pp-dev {FILENAME}"),
            ("POSTPROCESSOR_LEGACY", "/usr/local/bin/pp-dev {FILENAME}"),
            ("POSTPROCESSOR_TEXT", "python3 extract.py {FILENAME}"),
            ("POSTPROCESSOR_TIMEOUT", "120"),
            ("POSTPROCESSOR_DFI_IMAGE", "vendor/dfi:1"),
            ("POSTPROCESSOR_DFI_ENABLED", "false"),
        ]
    ]
    selected, skipped = select_postprocessors(settings)
    assert [setting.key for setting in selected] == ["POSTPROCESSOR_TEXT"]
    assert set(skipped) == {"POSTPROCESSOR_DFI", "POSTPROCESSOR_LEGACY"}
    enabled, skipped = select_postprocessors(settings, True)
    assert len(enabled) == 3 and skipped == {}


@pytest.mark.parametrize("enabled", [None, False, True])
def test_upload_skips_unavailable_dfi_only_when_disabled(
    authenticated, tmp_path, monkeypatch, enabled
):
    from io import BytesIO
    from app import db
    from app.models.cfg_settings import Cfg_settings
    from app.models.files import Files
    import app.postprocessing as postprocessing

    monkeypatch.delenv("POSTPROCESSOR_DFI_ENABLED", raising=False)
    db.session.add_all(
        [
            Cfg_settings(key="FILE_STORE_PATH", value=str(tmp_path / "samples")),
            Cfg_settings(
                key="POSTPROCESSING_FILE_STORE_PATH", value=str(tmp_path / "work")
            ),
            Cfg_settings(
                key="POSTPROCESSOR_DFI", value="/usr/local/bin/pp-dev {FILENAME}"
            ),
            *(
                [
                    Cfg_settings(
                        key="POSTPROCESSOR_DFI_ENABLED", value=str(enabled).lower()
                    )
                ]
                if enabled is not None
                else []
            ),
        ]
    )
    db.session.commit()

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("DFI vendor wrapper unavailable")

    monkeypatch.setattr(postprocessing, "run_postprocessor", unavailable)
    response = authenticated.post(
        "/ThreatKB/file_upload",
        data={"file": (BytesIO(b"harmless fixture"), "fixture.txt")},
    )
    if enabled:
        assert response.status_code == 422, response.json
        assert "DFI vendor wrapper unavailable" in response.get_data(as_text=True)
    else:
        assert response.status_code == 200, response.json
        assert response.json["postprocessing_skipped"] == {
            "POSTPROCESSOR_DFI": "Optional DFI preprocessing is disabled."
        }
        assert Files.query.count() == 1
        assert (
            tmp_path
            / "samples"
            / "None"
            / "None"
            / Files.query.one().sha1
            / "fixture.txt"
        ).read_bytes() == b"harmless fixture"
