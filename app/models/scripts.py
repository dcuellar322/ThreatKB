from app import db
import tempfile
import subprocess
import re


class Scripts(db.Model):
    __tablename__ = "scripts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(128), nullable=True)
    interpreter = db.Column(db.String(64), nullable=False)
    code = db.Column(db.TEXT(), nullable=True)
    match_regex = db.Column(db.String(4096), nullable=True)
    date_created = db.Column(
        db.DateTime(timezone=True), default=db.func.current_timestamp()
    )
    date_modified = db.Column(
        db.DateTime(timezone=True),
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )
    created_user_id = db.Column(
        db.Integer, db.ForeignKey("kb_users.id"), nullable=False
    )
    created_user = db.relationship(
        "KBUser",
        foreign_keys=created_user_id,
        primaryjoin="KBUser.id==Scripts.created_user_id",
    )

    def to_dict(self):
        return dict(
            id=self.id,
            name=self.name,
            description=self.description,
            code=self.code,
            interpreter=self.interpreter,
            match_regex=self.match_regex,
            date_created=self.date_created.isoformat(),
            date_modified=self.date_modified.isoformat(),
            created_user=self.created_user.to_dict(),
        )

    def run_script(self, arguments, highlight_lines_matching=None, timeout=10):
        import shlex

        with tempfile.TemporaryDirectory(prefix="threatkb-script-") as folder:
            from pathlib import Path

            path = Path(folder) / "script"
            path.write_text(self.code)
            command = [*shlex.split(self.interpreter), str(path), *map(str, arguments)]
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout
            )
        results = {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "retcode": proc.returncode,
            "command": shlex.join(command),
        }

        try:
            if self.match_regex:
                results["stdout"] = re.sub(
                    "(" + self.match_regex + ")", "<mark>\\1</mark>", results["stdout"]
                )
        except:
            pass

        try:
            if highlight_lines_matching:
                results["stdout"] = re.sub(
                    "(" + highlight_lines_matching + ")",
                    "<mark>\\1</mark>",
                    results["stdout"],
                )
        except:
            pass

        return results

    def __repr__(self):
        return "<Script %r>" % (self.id)
