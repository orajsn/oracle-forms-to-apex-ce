"""Closed profile routing; profile strings never become import paths."""
from . import native_blueprint, native_blueprint_required


def select(spec):
    """Select syntax only; callers still validate metadata and source authority."""
    if type(spec) is not dict or type(spec.get("schema_version")) is not int:
        raise ValueError("PROTOTYPE_PROFILE_UNSUPPORTED")
    if spec.get("profile_id") == native_blueprint.PROFILE_ID and spec["schema_version"] == 1:
        return native_blueprint
    if (spec.get("profile_id") == native_blueprint_required.PROFILE_ID
            and spec["schema_version"] == native_blueprint_required.SCHEMA_VERSION):
        return native_blueprint_required
    raise ValueError("PROTOTYPE_PROFILE_UNSUPPORTED")
