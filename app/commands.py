"""Local administration commands; credentials never enter tracked files."""
import click
from app import app, db, bcrypt
from app.models.users import KBUser


@app.cli.command("admin-user")
@click.option("--email", required=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True,
              envvar="THREATKB_ADMIN_PASSWORD")
def admin_user(email, password):
    """Create or recover a local administrator account."""
    if not password or len(password.encode()) > 72:
        raise click.ClickException("Password must contain 1 to 72 UTF-8 bytes.")
    user = KBUser.query.filter_by(email=email).first()
    if user is None:
        user = KBUser(email=email)
    user.password = bcrypt.generate_password_hash(password).decode()
    user.admin = True
    user.active = True
    db.session.add(user)
    db.session.commit()
    click.echo(f"Administrator ready: {email}")
