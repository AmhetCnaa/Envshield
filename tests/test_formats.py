from __future__ import annotations

from envshield.core.formats import (
    detect_format,
    dump_secrets,
    flatten_dict,
    parse_env_content,
    parse_json_content,
    parse_secrets,
    parse_toml_content,
)


def test_detect_format():
    assert detect_format("config.json") == "json"
    assert detect_format("vault.json.enc") == "json"
    assert detect_format("settings.toml") == "toml"
    assert detect_format("settings.toml.enc") == "toml"
    assert detect_format("app.yaml") == "yaml"
    assert detect_format("app.yml.enc") == "yaml"
    assert detect_format(".env") == "env"
    assert detect_format(".env.production.enc") == "env"
    assert detect_format("unknown.enc", '{"key": "val"}') == "json"


def test_flatten_dict():
    nested = {
        "database": {
            "host": "localhost",
            "port": 5432,
            "credentials": {"user": "admin", "active": True},
        },
        "tags": ["prod", "us-east"],
        "empty": None,
    }
    flattened = flatten_dict(nested)
    assert flattened["DATABASE__HOST"] == "localhost"
    assert flattened["DATABASE__PORT"] == "5432"
    assert flattened["DATABASE__CREDENTIALS__USER"] == "admin"
    assert flattened["DATABASE__CREDENTIALS__ACTIVE"] == "true"
    assert flattened["TAGS"] == "prod,us-east"
    assert flattened["EMPTY"] == ""


def test_parse_env_content():
    content = """
    # Comment
    export DB_NAME="prod_db"
    API_KEY='sk_live_123'
    EMPTY_VAL=
    """
    secrets = parse_env_content(content)
    assert secrets["DB_NAME"] == "prod_db"
    assert secrets["API_KEY"] == "sk_live_123"
    assert secrets["EMPTY_VAL"] == ""


def test_parse_json_and_toml():
    json_str = '{"app": {"name": "shield", "workers": 4}}'
    parsed_json = parse_json_content(json_str)
    assert parsed_json["APP__NAME"] == "shield"
    assert parsed_json["APP__WORKERS"] == "4"

    toml_str = 'title = "ShieldApp"\n[server]\nport = 8080'
    parsed_toml = parse_toml_content(toml_str)
    assert parsed_toml["TITLE"] == "ShieldApp"
    assert parsed_toml["SERVER__PORT"] == "8080"


def test_dump_secrets():
    data = {"APP_ENV": "staging", "PORT": "3000"}
    env_out = dump_secrets(data, "env")
    assert "APP_ENV=staging" in env_out
    assert "PORT=3000" in env_out

    json_out = dump_secrets(data, "json")
    assert '"APP_ENV": "staging"' in json_out

    toml_out = dump_secrets(data, "toml")
    assert 'APP_ENV = "staging"' in toml_out


def test_parse_secrets_auto():
    content = '{"api": "test"}'
    res = parse_secrets(content, format_type="auto", path_hint="data.json.enc")
    assert res["API"] == "test"
