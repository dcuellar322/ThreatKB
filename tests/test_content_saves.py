import importlib

import pytest

from app import app, db
from app.models.jobs import Job
from app.models.users import KBUser
from app.routes.jobs import execute_job

routes = importlib.import_module("app.routes.content")


@pytest.fixture
def draft(authenticated, monkeypatch, tmp_path, content_save):
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(tmp_path / "content"))
    return content_save("/ThreatKB/content/rules", {"name": "QueuedFixture"})


def submit(authenticated, draft, text=None):
    return authenticated.put(
        "/ThreatKB/content/rules/" + draft["id"],
        json={
            "yaml": text if text is not None else draft["yaml"] + "\n# Queued edit\n",
            "file_name": draft["file_name"],
            "revision": draft["revision"],
        },
    )


def deliver(response):
    assert response.status_code == 202, response.json
    return execute_job.apply(args=[response.json["id"]]).result


def test_save_defers_catalog_and_compilation_and_commits_once(
    authenticated, draft, monkeypatch
):
    head = routes.git("rev-parse", "HEAD")
    original_repo = routes.Repository

    def lightweight(*args, **kwargs):
        assert kwargs.get("load_rules") is False, "Web saves must not parse the catalog"
        return original_repo(*args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(routes, "Repository", lightweight)
        queued = submit(authenticated, draft)
    assert queued.status_code == 202 and queued.json["status"] == "queued"
    assert routes.git("rev-parse", "HEAD") == head
    assert (routes.content_root() / "rules" / draft["file_name"]).read_text() == draft[
        "yaml"
    ]
    result = deliver(queued)
    assert result["status"] == "succeeded"
    assert result["result"]["git_commit"] != head
    assert routes.git("status", "--porcelain") == ""
    assert execute_job.apply(args=[queued.json["id"]]).result is None
    assert routes.git("rev-parse", "HEAD") == result["result"]["git_commit"]
    assert "analyst@example.test" == routes.git("log", "-1", "--format=%an")


def test_missing_and_stale_revisions_do_not_queue(authenticated, draft):
    assert (
        authenticated.put(
            "/ThreatKB/content/rules/" + draft["id"],
            json={"yaml": draft["yaml"], "file_name": draft["file_name"]},
        ).status_code
        == 428
    )
    count = Job.query.count()
    (routes.content_root() / "external.txt").write_text("external change")
    assert submit(authenticated, draft).status_code == 409
    assert Job.query.count() == count


def test_two_queued_saves_cannot_overwrite_each_other(authenticated, draft):
    first = submit(authenticated, draft)
    second = submit(authenticated, draft, draft["yaml"] + "\n# Second edit\n")
    assert deliver(first)["status"] == "succeeded"
    result = deliver(second)
    assert result["status"] == "failed" and "changed" in result["error"]
    assert (
        "Second edit"
        not in (routes.content_root() / "rules" / draft["file_name"]).read_text()
    )


def test_failed_compilation_never_changes_live_source_or_index(
    authenticated, draft, monkeypatch
):
    import yara

    head = routes.git("rev-parse", "HEAD")
    target = routes.content_root() / "rules" / draft["file_name"]
    real_compile = yara.compile

    def compile_candidate(**kwargs):
        assert target.read_text() == draft["yaml"]
        assert routes.git("diff", "--cached") == ""
        return real_compile(**kwargs)

    monkeypatch.setattr(yara, "compile", compile_candidate)
    result = deliver(
        submit(
            authenticated,
            draft,
            draft["yaml"].replace(
                "condition: 'false'", "condition: missing_identifier"
            ),
        )
    )
    assert result["status"] == "failed" and "missing_identifier" in result["error"]
    assert target.read_text() == draft["yaml"]
    assert routes.git("rev-parse", "HEAD") == head
    assert routes.git("status", "--porcelain") == ""


def test_external_change_during_validation_is_preserved(
    authenticated, draft, monkeypatch
):
    import yara

    external = routes.content_root() / "external.txt"
    real_compile = yara.compile

    def compile_and_edit(**kwargs):
        external.write_text("external work")
        return real_compile(**kwargs)

    monkeypatch.setattr(yara, "compile", compile_and_edit)
    result = deliver(submit(authenticated, draft))
    assert result["status"] == "failed" and "during validation" in result["error"]
    assert external.read_text() == "external work"
    assert (routes.content_root() / "rules" / draft["file_name"]).read_text() == draft[
        "yaml"
    ]


def test_disabled_account_cannot_complete_queued_save(authenticated, draft):
    queued = submit(authenticated, draft)
    user = db.session.get(KBUser, 1)
    user.active = False
    db.session.commit()
    result = deliver(queued)
    assert result["status"] == "failed" and "active" in result["error"]


def test_settings_permissions_rechecked_and_generic_save_submission_blocked(
    authenticated, draft
):
    config = authenticated.get("/ThreatKB/content/config/macros").json
    queued = authenticated.put(
        "/ThreatKB/content/config/macros",
        json={"yaml": "{}\n# Configuration edit\n", "revision": config["revision"]},
    )
    user = db.session.get(KBUser, 1)
    user.admin = False
    db.session.commit()
    result = deliver(queued)
    assert result["status"] == "failed" and "Administrator" in result["error"]
    assert (
        authenticated.post(
            "/ThreatKB/jobs", json={"kind": "save_content", "payload": {}}
        ).status_code
        == 400
    )


def test_settings_validate_dependent_yara_and_support_noop(authenticated, draft):
    config = authenticated.get("/ThreatKB/content/config/categories").json
    failed = deliver(
        authenticated.put(
            "/ThreatKB/content/config/categories",
            json={"yaml": "OTHER: Other\n", "revision": config["revision"]},
        )
    )
    assert failed["status"] == "failed" and "Unknown category" in failed["error"]
    head = routes.git("rev-parse", "HEAD")
    noop = deliver(submit(authenticated, draft, draft["yaml"]))
    assert noop["status"] == "succeeded" and not noop["result"]["changed"]
    assert routes.git("rev-parse", "HEAD") == head


def test_queue_unavailable_keeps_source_unchanged(authenticated, draft, monkeypatch):
    def unavailable(**kwargs):
        raise ConnectionError("No broker")

    monkeypatch.setattr(execute_job, "apply_async", unavailable)
    response = submit(authenticated, draft)
    assert response.status_code == 503
    assert Job.query.order_by(Job.created_at.desc()).first().status == "failed"
    assert (routes.content_root() / "rules" / draft["file_name"]).read_text() == draft[
        "yaml"
    ]


def test_permission_revoked_during_validation_prevents_commit(
    authenticated, draft, monkeypatch
):
    import yara

    config = authenticated.get("/ThreatKB/content/config/macros").json
    head = routes.git("rev-parse", "HEAD")
    queued = authenticated.put(
        "/ThreatKB/content/config/macros",
        json={"yaml": "{}\n# New macro settings\n", "revision": config["revision"]},
    )
    real_compile = yara.compile

    def revoke_after_validation(**kwargs):
        compiled = real_compile(**kwargs)
        db.session.get(KBUser, 1).admin = False
        db.session.commit()
        return compiled

    monkeypatch.setattr(yara, "compile", revoke_after_validation)
    result = deliver(queued)
    assert result["status"] == "failed" and "Administrator" in result["error"]
    assert routes.git("rev-parse", "HEAD") == head
    assert routes.git("status", "--porcelain") == ""


def test_git_commit_failure_rolls_back_only_the_submitted_file(
    authenticated, draft, monkeypatch
):
    import subprocess

    head = routes.git("rev-parse", "HEAD")
    queued = submit(authenticated, draft)
    real_git = routes.git

    def fail_commit(*args):
        if "commit" in args:
            raise subprocess.CalledProcessError(1, ["git", "commit"])
        return real_git(*args)

    monkeypatch.setattr(routes, "git", fail_commit)
    result = deliver(queued)
    assert result["status"] == "failed"
    assert routes.git("rev-parse", "HEAD") == head
    assert routes.git("status", "--porcelain") == ""
    assert (routes.content_root() / "rules" / draft["file_name"]).read_text() == draft[
        "yaml"
    ]
