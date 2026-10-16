import json
import zipfile
from app import db
from app.models.cfg_states import Cfg_states
from app.models.cfg_settings import Cfg_settings
from app.models.releases import Release
from app.release_storage import release_workspace


def test_release_workspace_is_configurable_and_export_zip_is_finished(client, tmp_path):
    db.session.add(Cfg_settings(key="RELEASE_DATA_PATH", value=str(tmp_path)))
    db.session.execute(
        Cfg_states.__table__.insert().values(state="Released", is_release_state=1)
    )
    db.session.commit()
    assert release_workspace() == tmp_path
    release = Release()
    release.release_data = json.dumps(
        {"Signatures": {"Signatures": {}}, "IP": {"IP": {}}, "DNS": {"DNS": {}}}
    )
    stream = release.generate_artifact_export()
    with zipfile.ZipFile(stream) as archive:
        assert archive.testzip() is None
    stream.close()
