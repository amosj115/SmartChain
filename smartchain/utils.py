def safe_int(value, default=None):
    """Return a validated integer or default for empty/invalid input."""
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return default
    try:
        integer = int(value)
        if isinstance(value, float) and value != integer:
            return default
        return integer
    except (TypeError, ValueError, OverflowError):
        return default
