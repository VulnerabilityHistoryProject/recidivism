import configparser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG_FILE = REPO_ROOT / "recidivism.ini"
DEFAULT_CONFIG_FILE = REPO_ROOT / "recidivism.default.ini"


def load_config(section: str) -> configparser.SectionProxy:
    config = configparser.ConfigParser()

    if LOCAL_CONFIG_FILE.exists():
        config.read(LOCAL_CONFIG_FILE, encoding="utf-8")
    else:
        print(
            "Missing recidivism.ini. Copy recidivism.default.ini to recidivism.ini "
            "and update local input/output paths."
        )
        if not DEFAULT_CONFIG_FILE.exists():
            raise FileNotFoundError(
                f"Could not find {LOCAL_CONFIG_FILE} or fallback {DEFAULT_CONFIG_FILE}."
            )
        config.read(DEFAULT_CONFIG_FILE, encoding="utf-8")

    if section not in config:
        raise KeyError(f"Missing [{section}] section in configuration file.")

    return config[section]


def resolve_config_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path.resolve()
    return (REPO_ROOT / path).resolve()
