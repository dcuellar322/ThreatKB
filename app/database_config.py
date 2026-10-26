"""Database connection configuration without interpolating raw credentials into URLs."""

from sqlalchemy.engine import URL


def database_url(default, environment):
    if environment.get("THREATKB_DATABASE_HOST"):
        return URL.create(
            "mysql+pymysql",
            username=environment.get("THREATKB_DATABASE_USER", "threatkb"),
            password=environment["THREATKB_DATABASE_PASSWORD"],
            host=environment["THREATKB_DATABASE_HOST"],
            port=int(environment.get("THREATKB_DATABASE_PORT", "3306")),
            database=environment.get("THREATKB_DATABASE_NAME", "threatkb"),
            query={"charset": "utf8mb4"},
        )
    value = environment.get("THREATKB_DATABASE_URL", default)
    if isinstance(value, str) and value.startswith("mysql://"):
        value = "mysql+pymysql://" + value[8:]
    return value
