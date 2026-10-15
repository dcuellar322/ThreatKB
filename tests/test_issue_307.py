from app import db
from app.models.files import Files
from app.models.cfg_settings import Cfg_settings


def test_delete_one_uploaded_attachment_preserves_other_files(authenticated, tmp_path):
    db.session.add(Cfg_settings(key="FILE_STORE_PATH", value=str(tmp_path)))
    for filename, digest in [("one.bin", "a" * 40), ("two.bin", "b" * 40)]:
        directory = tmp_path / "1" / "1" / digest
        directory.mkdir(parents=True)
        (directory / filename).write_bytes(b"benign")
        db.session.add(
            Files(filename=filename, sha1=digest, entity_type=1, entity_id=1, user_id=1)
        )
    db.session.commit()
    assert authenticated.delete("/ThreatKB/files/1").status_code == 204
    assert not (tmp_path / "1" / "1" / ("a" * 40) / "one.bin").exists()
    assert (tmp_path / "1" / "1" / ("b" * 40) / "two.bin").exists()
    assert Files.query.count() == 1
