import configparser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG_FILE = REPO_ROOT / "recidivism.ini"
DEFAULT_CONFIG_FILE = REPO_ROOT / "recidivism.default.ini"


def load_config_with_source(section: str) -> tuple[configparser.SectionProxy, Path]:
    """Load configuration for a script section.

    Reads `recidivism.ini` from the repository root when present. If it is
    missing, prints local setup guidance and falls back to
    `recidivism.default.ini`. Raises KeyError when the requested section is not
    defined.

    Returns:
        Tuple of the requested section proxy and the config file path used.
    """
    config = configparser.ConfigParser()

    if LOCAL_CONFIG_FILE.exists():
        source = LOCAL_CONFIG_FILE
        config.read(source, encoding="utf-8")
    else:
        print(
            "Missing recidivism.ini. Copy recidivism.default.ini to recidivism.ini "
            "and update local input/output paths."
        )
        if not DEFAULT_CONFIG_FILE.exists():
            raise FileNotFoundError(
                f"Could not find {LOCAL_CONFIG_FILE} or fallback {DEFAULT_CONFIG_FILE}."
            )
        source = DEFAULT_CONFIG_FILE
        config.read(source, encoding="utf-8")

    if section not in config:
        raise KeyError(f"Missing [{section}] section in configuration file.")

    return config[section], source


def load_config(section: str) -> configparser.SectionProxy:
    """Backwards-compatible section-only loader."""
    config_section, _ = load_config_with_source(section)
    return config_section


def resolve_config_path(path_value: str) -> Path:
    """Resolve a configured path value.

    Absolute paths are normalized directly. Relative paths are interpreted
    relative to the repository root.

    Args:
        path_value: Path string from configuration or CLI.

    Returns:
        Fully resolved filesystem path.
    """
    path = Path(path_value)
    if path.is_absolute():
        return path.resolve()
    return (REPO_ROOT / path).resolve()


def get_required_value(config: configparser.SectionProxy, section: str, key: str) -> str:
    """Return a required non-empty configuration value.

    Args:
        config: Configuration section containing script settings.
        section: Section name for diagnostics.
        key: Config key to read.

    Returns:
        Non-empty configuration value.

    Raises:
        ValueError: If the key is missing or empty.
    """
    value = config.get(key, fallback=None)
    if value is None or not value.strip():
        raise ValueError(f"Missing required config key '{key}' in section [{section}].")
    return value
