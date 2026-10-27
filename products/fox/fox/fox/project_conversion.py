"""Deterministic, source-bound planning for one multi-form APEX application.

This module does no I/O and grants no execution or acceptance authority. It
composes the existing single-table assessor; it does not pretend that assessor
can merge forms. All selected sources are accounted for before rendering_spec
is emitted. Business code and ambiguous source intent remain explicit blockers.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
import re
import unicodedata
from xml.etree import ElementTree as XML

from defusedxml import ElementTree as ET

from . import intake, native_source


PROFILE_ID = "native-project-v1"
STORAGE_MAPPING_SCOPE = "fox-project-storage-v1"
_STORAGE_MAPPING_FIELDS = {"schema_version", "scope", "project_id", "source_table_name",
                           "source_schema_sha256", "identity_sha256", "target_table_name"}
MAX_SOURCE_FILES = 50
MAX_FORMS = 50
MAX_XML_ELEMENTS = 5000
MAX_XML_DEPTH = 128
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_APEX_SUBSTITUTION = re.compile(r"&[A-Za-z0-9_$#]+\.")
_NAMESPACES = {"", "http://xmlns.oracle.com/Forms"}
_DISPLAY_ONLY_OBJECTS = {"formmodule", "block", "item", "formitem", "canvas", "window"}
_HUMAN_CODES = {"BUSINESS_CODE_REVIEW_REQUIRED", "AMBIGUOUS_ITEM_PROMPT",
                "FORM_SELECTION_REQUIRED", "UNNAMED_FORM_MODULE", "LABEL_REVIEW_REQUIRED"}
_MISSING_CODES = {"DDL_REQUIRED", "EXPLICIT_KEY_REQUIRED", "ITEM_COLUMN_MISSING",
                  "COLUMN_ITEM_MAPPING_REQUIRED", "ITEM_MAPPING_REQUIRED"}


class ProjectConversionInputError(ValueError):
    """Invalid/stale request, not an invented assessment of untrusted bytes."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _label(value) -> bool:
    return (type(value) is str and native_source._label(value)
            and not _APEX_SUBSTITUTION.search(value))


def _tag(element) -> str:
    return native_source._tag(element)


def _namespace(element) -> str:
    return element.tag[1:].split("}", 1)[0] if element.tag.startswith("{") else ""


def _bounded_xml(root):
    """Avoid recursive serialization or finding expansion on excessive XML."""
    pending, count = [(root, 1)], 0
    while pending:
        element, depth = pending.pop()
        count += 1
        if count > MAX_XML_ELEMENTS or depth > MAX_XML_DEPTH:
            return False
        pending.extend((child, depth + 1) for child in element)
    return True


def _xml_property_issues(root, source):
    """Audit original elements before case/namespace-normalizing attributes."""
    issues = []
    metadata = {("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation"),
                ("http://www.w3.org/XML/1998/namespace", "space")}
    for index, element in enumerate(root.iter(), 1):
        location = f"{_tag(element)}[{index}]"
        if _namespace(element) not in _NAMESPACES:
            issues.append((element, _finding("XML_NAMESPACE_UNSUPPORTED", "UNSUPPORTED",
                "An element uses an unrecognized namespace; it is not interpreted as an Oracle Forms object.",
                source, location, owner="SOURCE_OWNER",
                action="Re-export a supported Forms XML document; do not rename foreign elements to make them pass.")))
        attributes = defaultdict(list)
        for name in element.attrib:
            namespace, local = (name[1:].split("}", 1) if name.startswith("{") else ("", name))
            attributes[local.casefold()].append(name)
            if namespace and (namespace, local) not in metadata:
                issues.append((element, _finding("XML_ATTRIBUTE_NAMESPACE_UNSUPPORTED", "UNSUPPORTED",
                    "A namespaced property has no supported Forms-property mapping.", source, location + ".@" + local,
                    owner="SOURCE_OWNER", action="Supply the authoritative Oracle Forms XML property, without foreign aliases.")))
        for local, originals in attributes.items():
            if len(originals) > 1:
                issues.append((element, _finding("AMBIGUOUS_XML_ATTRIBUTES", "NEEDS_HUMAN",
                    "Multiple XML properties normalize to the same name. No last-value selection is allowed.",
                    source, location + ".@" + local, owner="SOURCE_OWNER",
                    action="Resolve the conflicting property definitions in the authoritative source, then re-export.")))
    return issues


def _finding(code, category, message, source=None, evidence=None, *, owner=None, action=None):
    return {"code": code, "category": category, "message": message,
            "source": source, "evidence": evidence,
            "owner": owner or {"NEEDS_HUMAN": "BUSINESS_OWNER", "MISSING_INPUT": "SOURCE_OWNER",
                               "UNSUPPORTED": "OPERATOR"}[category],
            "required_action": action or {
                "NEEDS_HUMAN": "Confirm the intended behavior and supply an explicit supported mapping; do not guess.",
                "MISSING_INPUT": "Supply the authoritative source or definition, then reassess this source version.",
                "UNSUPPORTED": "Ask the technical owner to implement and validate this mapping; no behavior will be silently discarded.",
            }[category]}


def _native_finding(value, *, requiredness_conflicts=()):
    code = value["code"]
    conflict = code == "ITEM_BEHAVIOR_REVIEW_REQUIRED" and value.get("evidence") in requiredness_conflicts
    category = ("NEEDS_HUMAN" if code in _HUMAN_CODES or conflict else
                "MISSING_INPUT" if code in _MISSING_CODES else "UNSUPPORTED")
    return _finding(code, category, value["message"], value.get("source"), value.get("evidence"))


def schema_fingerprint(spec: dict) -> str:
    """Shared physical schema identity; display labels are deliberately excluded."""
    value = {key: deepcopy(item) for key, item in spec.items() if key != "columns"}
    value["columns"] = [{key: item for key, item in column.items() if key != "label"}
                        for column in spec["columns"]]
    return _sha(_canonical(value))


def _storage_require(condition, message):
    if not condition:
        raise ProjectConversionInputError("STORAGE_MAPPING_INVALID", message)


def _validate_storage_spec(spec, *, physical=False):
    """Validate the parser's exact typed subset, without adding source semantics."""
    _storage_require(type(spec) is dict and set(spec) == {
        "profile_id", "data_mode", "table_name", "columns", "supported_operations"},
        "Storage mapping requires the complete typed native schema.")
    _storage_require(spec["profile_id"] == native_source.PROFILE_ID
        and spec["data_mode"] == native_source.DATA_MODE
        and spec["supported_operations"] == ["query", "insert", "update"],
        "Storage mapping does not widen native operations or data mode.")

    def identifier(value):
        try:
            return native_source._identifier(value) == value
        except native_source._Unsupported:
            return False

    _storage_require(identifier(spec["table_name"])
        and (not physical or spec["table_name"].startswith("FOX_NATIVE_")),
        "Storage table names must be canonical safe identifiers.")
    columns = spec["columns"]
    _storage_require(type(columns) is list and 2 <= len(columns) <= 20,
                     "Storage mapping requires 2 to 20 explicit columns.")
    names, keys = set(), 0
    for column in columns:
        _storage_require(type(column) is dict, "Storage columns must be typed objects.")
        required = {"name", "data_type", "nullable", "label", "primary_key", "identity"}
        fields = required | ({"length"} if column.get("data_type") == "VARCHAR2" else set())
        _storage_require(set(column) == fields and identifier(column.get("name"))
            and column["name"] not in names and type(column.get("data_type")) is str
            and column["data_type"] in {"NUMBER", "DATE", "VARCHAR2"}
            and all(type(column.get(key)) is bool for key in ("nullable", "primary_key", "identity"))
            and _label(column.get("label")), "Storage column metadata is not the supported typed subset.")
        names.add(column["name"])
        _storage_require(column["primary_key"] == column["identity"]
            and (not column["primary_key"] or (column["data_type"] == "NUMBER" and not column["nullable"])),
            "Storage mapping must preserve the explicit non-null NUMBER identity primary key.")
        keys += column["primary_key"]
        if column["data_type"] == "VARCHAR2":
            _storage_require(type(column["length"]) is int and 1 <= column["length"] <= 4000,
                             "Storage VARCHAR2 length is outside the supported subset.")
    _storage_require(keys == 1, "Storage mapping requires exactly one explicit identity primary key.")


def _storage_identity(project_id, source_table_name, source_schema_sha256):
    return {"schema_version": 1, "scope": STORAGE_MAPPING_SCOPE, "project_id": project_id,
            "source_table_name": source_table_name, "source_schema_sha256": source_schema_sha256}


def _storage_identity_sha(identity):
    return _sha(_canonical(identity))


def derive_storage_mapping(project_id: str, source_spec: dict) -> dict:
    """Derive project-isolated synthetic storage from validated original metadata.

    No source bytes, labels, filenames, jobs or project display names participate.
    Structural column order is significant; structural revisions get new storage,
    never an implied ALTER, migration or data copy.
    """
    _storage_require(type(project_id) is str and _PROJECT_ID.fullmatch(project_id),
                     "Storage mapping requires a stable project identity.")
    _validate_storage_spec(source_spec)
    identity = _storage_identity(project_id, source_spec["table_name"], schema_fingerprint(source_spec))
    digest = _storage_identity_sha(identity)
    _storage_require(type(digest) is str and _SHA.fullmatch(digest), "Storage identity digest is invalid.")
    return {**identity, "identity_sha256": digest, "target_table_name": "FOX_NATIVE_" + digest[:19].upper()}


def validate_storage_mapping(value: dict, *, project_id: str, native_form: dict) -> dict:
    """Recompute a mapping from physical metadata; never trust its declared hashes."""
    _storage_require(type(value) is dict and set(value) == _STORAGE_MAPPING_FIELDS,
                     "Storage mapping must use the exact versioned field set.")
    _storage_require(type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["scope"] == STORAGE_MAPPING_SCOPE and value["project_id"] == project_id,
        "Storage mapping version or project binding changed.")
    _validate_storage_spec(native_form, physical=True)
    source_spec = deepcopy(native_form)
    source_spec["table_name"] = value["source_table_name"]
    expected = derive_storage_mapping(project_id, source_spec)
    _storage_require(value == expected and native_form["table_name"] == expected["target_table_name"],
                     "Storage mapping does not match the project and original structural schema.")
    return expected


def _validate_ddl_sources(values):
    _storage_require(type(values) is list and bool(values), "Original DDL references are required.")
    names = []
    for value in values:
        _storage_require(type(value) is dict and set(value) == {"name", "sha256"},
                         "DDL references require only the original filename and SHA-256.")
        name = value["name"]
        _storage_require(type(name) is str and 1 <= len(name) <= 180 and name.lower().endswith(".sql")
            and not any(part in name for part in ("/", "\\", ":", ".."))
            and not any(ord(char) < 32 for char in name)
            and type(value["sha256"]) is str and _SHA.fullmatch(value["sha256"]),
            "DDL references must preserve safe original source names and hashes.")
        names.append(name)
    _storage_require(names == sorted(names) and len({name.casefold() for name in names}) == len(names),
                     "DDL references must be unique and ordered by original filename.")


def validate_project_storage_mappings(forms: list[dict], *, project_id: str) -> list[dict]:
    """Validate every mapping and detect truncated/full identity and schema collisions."""
    _storage_require(type(forms) is list and 1 <= len(forms) <= MAX_FORMS,
                     "Validate all forms in the project storage envelope.")
    mappings, targets, identities, sources = [], {}, {}, {}
    for form in forms:
        _storage_require(type(form) is dict, "Storage forms must be objects.")
        mapping = validate_storage_mapping(form.get("storage_mapping"), project_id=project_id,
                                           native_form=form.get("native_form"))
        _validate_ddl_sources(form.get("ddl_sources"))
        identity = _storage_identity(project_id, mapping["source_table_name"], mapping["source_schema_sha256"])
        for seen, key, value in ((targets, mapping["target_table_name"], mapping["identity_sha256"]),
                                 (identities, mapping["identity_sha256"], identity),
                                 (sources, mapping["source_table_name"], mapping["source_schema_sha256"])):
            if key in seen and seen[key] != value:
                raise ProjectConversionInputError("STORAGE_MAPPING_COLLISION",
                    "Distinct source storage identities collide or disagree; no storage was selected.")
            seen[key] = value
        mappings.append(mapping)
    return mappings


def _validated_source_bytes(files):
    if type(files) is not list:
        raise ProjectConversionInputError("SOURCE_LIST_REQUIRED", "Supply a complete selected source version.")
    values, names = [], set()
    for item in files:
        if (type(item) is not dict or type(item.get("name")) is not str or type(item.get("text")) is not str
                or type(item.get("sha256")) is not str or not _SHA.fullmatch(item["sha256"])
                or type(item.get("bytes")) is not int):
            raise ProjectConversionInputError("SOURCE_RECORD_INVALID", "The selected source metadata is invalid; reload the project.")
        name = item["name"]
        if (not name or len(name) > 180 or any(part in name for part in ("/", "\\", ":", ".."))
                or any(ord(char) < 32 for char in name)):
            raise ProjectConversionInputError("SOURCE_NAME_INVALID", "Use simple source filenames without directory paths.")
        if name.casefold() in names:
            raise ProjectConversionInputError("DUPLICATE_SOURCE_NAME", "Source filenames must be unique, including case.")
        names.add(name.casefold())
        try:
            text_bytes = item["text"].encode("utf-8")
        except UnicodeEncodeError:
            raise ProjectConversionInputError("SOURCE_ENCODING_INVALID", "Prepare valid UTF-8 source text.") from None
        # checked_source preserves original upload hashes while decoding a UTF-8
        # BOM. Reconstruct only those two explicit encodings, never normalize
        # newlines or trust a supplied digest that does not match the text.
        candidates = (text_bytes, b"\xef\xbb\xbf" + text_bytes)
        raw = next((value for value in candidates if len(value) == item["bytes"]
                    and _sha(value) == item["sha256"]), None)
        if raw is None:
            raise ProjectConversionInputError("SOURCE_BYTES_CHANGED", "The selected source bytes changed; reload and reassess.")
        if not raw or len(raw) > intake.MAX_FILE_BYTES:
            raise ProjectConversionInputError("SOURCE_FILE_SIZE", "Each readable source must be nonempty and at most 5 MB.")
        values.append(({key: item[key] for key in ("name", "text", "sha256", "bytes")}, raw))
    return sorted(values, key=lambda pair: pair[0]["name"])


def _definitions(files, roots):
    definitions = defaultdict(set)
    for source in files:
        name = source["name"]
        if name in roots:
            root = roots[name]
            for element in root.iter():
                attrs = native_source._attrs(element)
                kind = {"formmodule": "module", "menumodule": "module", "objectlibrary": "module",
                        "librarymodule": "library"}.get(_tag(element))
                if kind and attrs.get("name"):
                    definitions[(kind, attrs["name"].upper())].add(name)
                if _tag(element) == "librarymodule" and attrs.get("sourcefile", "").lower().endswith(".pll"):
                    definitions[("library", PurePosixPath(attrs["sourcefile"]).stem.upper())].add(name)
                if (root.tag == "{urn:fox:forms-library:v1}Module"
                        and root.get("Format") == "FOX-JDAPI-LIBRARY-1"
                        and root.get("DatabaseConnected") == "false"
                        and _tag(element) == "programunit" and attrs.get("programunittype") in {"3", "4"}
                        and attrs.get("name")):
                    definitions[("package" if attrs["programunittype"] == "3" else "package_body",
                                 attrs["name"].upper())].add(name)
        else:
            for match in intake.CREATE_DEFINITION.finditer(source["text"]):
                kind = match[1].lower().replace(" ", "_")
                target = re.sub(r"\s+", "", match[2]).upper()
                definitions[(kind, target)].add(name)
            if name.lower().endswith(".pld"):
                definitions[("library", PurePosixPath(name).stem.upper())].add(name)
    return definitions


def _dependencies(fragment, source_name, definitions, module):
    checked = intake.checked_source(source_name, fragment.encode("utf-8"))
    result = intake.inventory([checked])["dependencies"]
    scoped = defaultdict(set, {key: set(value) for key, value in definitions.items()})
    local_packages = set()
    for element in module.iter():
        attrs = native_source._attrs(element)
        if _tag(element) == "programunit" and attrs.get("programunittype") in {"3", "4"} and attrs.get("name"):
            kind = "package" if attrs["programunittype"] == "3" else "package_body"
            target = attrs["name"].upper()
            scoped[(kind, target)].add(source_name)
            local_packages.add(target)
    providers = set()
    for item in result:
        kinds = ("package", "package_body") if item["kind"] == "package" else (item["kind"],)
        complete = all(scoped.get((kind, item["target"])) for kind in kinds)
        for kind in kinds:
            providers.update(scoped.get((kind, item["target"]), ()))
        item["status"] = "SOURCE_PRESENT" if complete else "MISSING"
        item["action"] = ("Review supplied source for behavioral coverage." if complete else
                          "Upload both package specification and body." if item["kind"] == "package" else
                          "Upload the referenced " + item["kind"] + " source.")
        if complete and item["kind"] == "package" and item["target"] in local_packages:
            item["action"] = "Review the supplied module-local program; it is not proof of a shared database package."
    return result, providers


def _rendering_spec(result):
    mapped = any("storage_mapping" in form for form in result["forms"])
    if any(type(form.get("table_name")) is str and not form["table_name"].startswith("FOX_NATIVE_")
           for form in result["forms"]):
        _storage_require(mapped, "Original-name project forms require explicit storage mapping metadata.")
    keys = ("module_id", "form_name", "source_name", "source_sha256", "native_form")
    if mapped:
        validate_project_storage_mappings(result["forms"], project_id=result["project_id"])
        keys += ("ddl_sources", "storage_mapping")
    spec = {"schema_version": 2 if mapped else 1, "profile_id": PROFILE_ID,
            "data_mode": "synthetic_test_only", "project_name": result["project_name"],
            "source_manifest_sha256": result["source_hash"], "forms": [
                {key: deepcopy(form[key]) for key in keys}
                for form in sorted(result["forms"], key=lambda item: item["module_id"])]}
    if mapped:
        spec["project_id"] = result["project_id"]
    return spec


def _finish(result):
    for form in result["forms"]:
        categories = {item["category"] for item in form["findings"]}
        form["state"] = next((state for state in ("NEEDS_HUMAN", "MISSING_INPUT", "UNSUPPORTED")
                              if state in categories), "READY")
    result["forms"].sort(key=lambda item: item["module_id"])
    if not result["source_files"]:
        result["state"] = "EMPTY"
    elif (result["assessment_complete"] and result["forms"] and not result["project_findings"]
          and all(form["state"] == "READY" for form in result["forms"])):
        result["state"] = "READY"
    else:
        result["state"] = "BLOCKED"
    result["can_generate"] = result["state"] == "READY"
    for index, form in enumerate(result["forms"]):
        if form["state"] == "READY":
            form["planned_pages"] = {"report_page": 2 * index + 1, "form_page": 2 * index + 2}
            form["mapping"] = [{"source_component": form["table_name"], "target_component": kind,
                                "status": "PLANNED_NOT_GENERATED"} for kind in ("native_report", "native_form")]
    result["summary"] = {"form_count": len(result["forms"]),
        **{name: sum(form["state"] == state for form in result["forms"]) for name, state in
           (("ready_forms", "READY"), ("missing_input_forms", "MISSING_INPUT"),
            ("needs_human_forms", "NEEDS_HUMAN"), ("unsupported_forms", "UNSUPPORTED"))},
        "blocking_findings": len(result["project_findings"]) + sum(len(form["findings"]) for form in result["forms"]),
        "unassessed_sources": 0 if result["assessment_complete"] else len(result["source_files"])}
    if result["can_generate"]:
        # Mapping is typed metadata only, after every original source matched and
        # passed. A mixed project maps *all* tables, including prefixed sources.
        if any(not form["table_name"].startswith("FOX_NATIVE_") for form in result["forms"]):
            for form in result["forms"]:
                mapping = derive_storage_mapping(result["project_id"], form["native_form"])
                form["storage_mapping"] = mapping
                form["native_form"]["table_name"] = mapping["target_table_name"]
        result["rendering_spec"] = _rendering_spec(result)
    result["plan_sha256"] = _sha(_canonical(result))
    return result


def assess_project_conversion(files: list[dict], *, project_id: str, project_name: str, source_hash: str) -> dict:
    """Plan all selected forms as one app; READY is not execution permission.

    files are existing checked_source records (additional storage fields are
    ignored). source_hash must identify that complete, exact selected version.
    HTTP callers must recompute this plan server-side before processing; never
    trust a client-submitted rendering_spec or can_generate flag.
    """
    if type(project_id) is not str or not _PROJECT_ID.fullmatch(project_id):
        raise ProjectConversionInputError("PROJECT_ID_INVALID", "A valid project identity is required.")
    if type(project_name) is not str or not _label(project_name.strip()):
        raise ProjectConversionInputError("PROJECT_NAME_INVALID", "Use a plain project name of 1 to 80 characters without APEX substitutions.")
    pairs = _validated_source_bytes(files)
    manifest = "\n".join(item["name"] + ":" + item["sha256"] for item, _ in pairs)
    if type(source_hash) is not str or not _SHA.fullmatch(source_hash) or source_hash != _sha(manifest.encode("utf-8")):
        raise ProjectConversionInputError("SOURCE_VERSION_CHANGED", "The selected source version changed; reload before processing.")
    result = {"schema_version": 1, "scope": "fox-project-conversion-plan-v1", "profile_id": PROFILE_ID,
        "project_id": project_id, "project_name": project_name.strip(), "source_hash": source_hash,
        "state": "BLOCKED", "can_generate": False, "assessment_complete": True,
        "forms": [], "project_findings": [], "source_files": [], "rendering_spec": None,
        "scope_note": "Planning only for the supported synthetic native profile. No application generated, import verified or business acceptance recorded."}
    source_views = {}
    for item, _ in pairs:
        suffix = PurePosixPath(item["name"]).suffix.lower()
        view = {"name": item["name"], "sha256": item["sha256"], "bytes": item["bytes"],
                "kind": "FORM_XML" if suffix == ".xml" else "TABLE_DDL" if suffix == ".sql" else "SUPPORTING_SOURCE",
                "module_ids": [], "disposition": "UNASSIGNED"}
        result["source_files"].append(view); source_views[item["name"]] = view
    if len(pairs) > MAX_SOURCE_FILES or sum(len(item["text"].encode("utf-8")) for item, _ in pairs) > intake.MAX_CONVERSION_BYTES:
        result["assessment_complete"] = False
        result["project_findings"].append(_finding("PROJECT_CAPACITY_LIMIT", "UNSUPPORTED",
            "This source version exceeds 50 files or 300 KB; no partial assessment or generation was performed.",
            action="Reduce the complete selected source set or ask the operator for a validated larger-capacity profile."))
        for view in result["source_files"]: view["disposition"] = "BLOCKED"
        return _finish(result)
    checked = []
    for item, raw in pairs:
        try:
            value = intake.checked_source(item["name"], raw)
        except ValueError as error:
            raise ProjectConversionInputError("SOURCE_INTAKE_REJECTED", str(error)) from None
        if value != item:
            raise ProjectConversionInputError("SOURCE_TEXT_CHANGED", "The stored readable text differs from its original upload; reload the source version.")
        checked.append(value)
    if not checked:
        result["project_findings"].append(_finding("SOURCES_REQUIRED", "MISSING_INPUT", "Add readable Forms XML and its authoritative table definitions."))
        return _finish(result)

    roots, tables, rejected_tables = {}, defaultdict(list), defaultdict(list)
    modules = []
    for source in checked:
        name = source["name"]
        if name.lower().endswith(".sql"):
            try:
                spec = native_source._parse_ddl(source["text"], allow_original_table=True)
                tables[spec["table_name"]].append((source, spec))
            except native_source._Unsupported as error:
                finding = _native_finding({"code": error.code, "message": str(error), "source": name})
                result["project_findings"].append(finding)
                source_views[name]["disposition"] = "BLOCKED"
                # Header evidence associates a rejection, never admits a schema.
                # Unrelated bad SQL must not hide a genuinely missing definition.
                try:
                    try:
                        header_text = native_source._strip_comments(source["text"])
                    except native_source._Unsupported:
                        # An exact leading header can still locate a rejected
                        # definition whose remainder has a malformed comment.
                        header_text = source["text"]
                    header = re.match(r"\s*CREATE\s+TABLE\s+([^\s(]+)", header_text, re.I)
                    if header:
                        rejected_tables[native_source._identifier(header[1])].append((source, finding))
                except native_source._Unsupported:
                    pass
        elif name.lower().endswith(".xml"):
            root = ET.fromstring(source["text"], forbid_dtd=True, forbid_entities=True, forbid_external=True)
            if not _bounded_xml(root):
                result["forms"] = []
                result["assessment_complete"] = False
                result["project_findings"] = [_finding("XML_STRUCTURE_LIMIT", "UNSUPPORTED",
                    "XML exceeds 5,000 elements or 128 nested levels; no partial assessment or generation was performed.", name,
                    action="Prepare a smaller supported source or ask the operator for a validated larger-capacity profile.")]
                for view in result["source_files"]:
                    view["disposition"] = "BLOCKED"; view["module_ids"] = []
                return _finish(result)
            roots[name] = root
            found = [element for element in root.iter() if _tag(element) == "formmodule"]
            direct = [root] if _tag(root) == "formmodule" else list(root) if _tag(root) == "module" else []
            counts = Counter(_key(native_source._attrs(element).get("name", "").strip()) for element in found)
            occurrences = Counter()
            included = set(element for module in found for element in module.iter())
            properties = _xml_property_issues(root, name) if found else []
            for element, finding in properties:
                if element not in included:
                    result["project_findings"].append(finding)
                    source_views[name]["disposition"] = "BLOCKED"
            outside = [element for element in root.iter() if element not in included and element is not root]
            outside_text = bool(root.text and root.text.strip()) if root not in included else False
            outside_text = outside_text or any(element.tail and element.tail.strip() for element in found if element in direct)
            envelope_code = root not in included and any(value.strip() for key, value in native_source._attrs(root).items()
                                                       if key in native_source._CODE_ATTRIBUTES)
            if found and (outside or outside_text or envelope_code):
                result["project_findings"].append(_finding("UNMAPPED_XML_CONTENT", "NEEDS_HUMAN",
                    "Selected XML contains content outside its FormModules; it cannot be discarded during composition.", name,
                    "XML envelope/sibling content"))
                source_views[name]["disposition"] = "BLOCKED"
            if not found:
                source_views[name]["kind"] = "SUPPORTING_SOURCE" if _tag(root) in {"module", "librarymodule", "menumodule", "objectlibrary"} else "UNSUPPORTED_XML"
            for element in found:
                form_name = native_source._attrs(element).get("name", "").strip()
                key = _key(form_name); occurrences[key] += 1
                occurrence = occurrences[key] if counts[key] > 1 else 0
                module_id = "form-" + _sha(_canonical([project_id, name, form_name, occurrence]))[:20]
                display_name = form_name if _label(form_name) else "Form in " + name[:60]
                form = {"module_id": module_id, "form_name": display_name, "source_name": name,
                    "source_sha256": source["sha256"], "state": "UNSUPPORTED", "table_name": None,
                    "native_form": None, "findings": [], "dependencies": [], "ddl_sources": [],
                    "planned_pages": None, "mapping": []}
                if not _label(form_name):
                    form["findings"].append(_finding("FORM_NAME_REVIEW_REQUIRED", "NEEDS_HUMAN",
                        "Provide an explicit plain form name of 1 to 80 characters without APEX substitutions.", name, "FormModule.Name"))
                descendants = set(element.iter())
                form["findings"].extend(deepcopy(finding) for owner, finding in properties if owner in descendants)
                if (element not in direct or _namespace(root) not in _NAMESPACES or _namespace(element) not in _NAMESPACES):
                    form["findings"].append(_finding("FORM_ENVELOPE_UNSUPPORTED", "UNSUPPORTED",
                        "Nested or unrecognized XML FormModules are not automatically selected or flattened.", name, "FormModule location/namespace"))
                source_views[name]["module_ids"].append(module_id)
                modules.append((form, element)); result["forms"].append(form)
    if len(modules) > MAX_FORMS:
        result["forms"] = []
        result["assessment_complete"] = False
        result["project_findings"] = [_finding("FORM_CAPACITY_LIMIT", "UNSUPPORTED",
            "This source version contains more than 50 FormModules; no partial assessment or app generation was performed.",
            action="Use a smaller complete project or ask for a validated larger-capacity profile.")]
        for view in result["source_files"]:
            view["disposition"] = "BLOCKED"; view["module_ids"] = []
        return _finish(result)
    if len({form["module_id"] for form, _ in modules}) != len(modules):
        raise ProjectConversionInputError("MODULE_ID_COLLISION", "Distinct forms could not be assigned unique identities; no plan was produced.")
    definitions = _definitions(checked, roots)
    source_table_names = set(tables) | set(rejected_tables)
    for _, module in modules:
        for element in module.iter():
            if _tag(element) == "block":
                try:
                    source_table_names.add(native_source._identifier(
                        native_source._attrs(element).get("querydatasourcename", "").strip()))
                except native_source._Unsupported:
                    pass
    original_name_project = any(not table.startswith("FOX_NATIVE_") for table in source_table_names)
    name_counts = Counter(_key(native_source._attrs(module).get("name", "").strip()) for _, module in modules)
    for form, module in modules:
        name, module_id = form["source_name"], form["module_id"]
        if name_counts[_key(native_source._attrs(module).get("name", "").strip())] > 1:
            form["findings"].append(_finding("DUPLICATE_FORM_NAME", "NEEDS_HUMAN",
                "Multiple selected modules use this form name. Choose the authoritative versions or provide distinct names.", name,
                "FormModule.Name", owner="SOURCE_OWNER"))
        fragment_node = deepcopy(module)
        fragment_node.tail = None  # The original tail was audited above.
        fragment = XML.tostring(fragment_node, encoding="unicode")
        dependencies, providers = _dependencies(fragment, name, definitions, module)
        form["dependencies"] = dependencies
        for provider in providers:
            if module_id not in source_views[provider]["module_ids"]:
                source_views[provider]["module_ids"].append(module_id)
        for dependency in dependencies:
            if dependency["status"] == "MISSING":
                form["findings"].append(_finding("MISSING_DEPENDENCY", "MISSING_INPUT",
                    "A referenced " + dependency["kind"] + " source is missing: " + dependency["target"] + ".", name,
                    dependency["evidence"], action=dependency["action"]))
        blocks = [element for element in module.iter() if _tag(element) == "block"]
        matches = []
        table_ambiguous = len(blocks) != 1
        if table_ambiguous:
            form["findings"].append(_finding("BLOCK_SELECTION_REQUIRED", "UNSUPPORTED",
                "Each form in this profile needs exactly one table-backed block; no block is silently chosen or discarded.", name))
        if len(blocks) == 1:
            try:
                form["table_name"] = native_source._identifier(native_source._attrs(blocks[0]).get("querydatasourcename", "").strip())
                matches = tables.get(form["table_name"], [])
            except native_source._Unsupported as error:
                table_ambiguous = True
                form["findings"].append(_finding(error.code, "UNSUPPORTED",
                    "Block.QueryDataSourceName must be one explicit unqualified supported table name.", name, "Block.QueryDataSourceName"))
        # Preserve historical all-prefixed blocked-plan bytes as well as READY
        # plans. Original-name/mixed projects use the clearer new diagnostics.
        rejected = rejected_tables.get(form["table_name"], []) if original_name_project else []
        if matches:
            form["ddl_sources"] = [{"name": source["name"], "sha256": source["sha256"]} for source, _ in matches]
            for source, _ in matches:
                if module_id not in source_views[source["name"]]["module_ids"]:
                    source_views[source["name"]]["module_ids"].append(module_id)
            if len({schema_fingerprint(spec) for _, spec in matches}) > 1:
                table_ambiguous = True
                form["findings"].append(_finding("SHARED_SCHEMA_CONFLICT", "NEEDS_HUMAN",
                    "Selected definitions disagree about this table. Supply one authoritative schema; no version is chosen automatically.", name,
                    form["table_name"], owner="SOURCE_OWNER"))
                selected = []
            else:
                selected = [matches[0][0]]
        else:
            selected = []
        if rejected:
            form["findings"].extend(deepcopy(finding) for _, finding in rejected)
            form["ddl_sources"] = sorted(form["ddl_sources"] + [
                {"name": source["name"], "sha256": source["sha256"]} for source, _ in rejected], key=lambda item: item["name"])
            for source, _ in rejected:
                if module_id not in source_views[source["name"]]["module_ids"]:
                    source_views[source["name"]]["module_ids"].append(module_id)
        native = native_source._assess_native_source([{"name": name, "text": fragment}, *selected],
                                                     allow_original_table=True)
        requiredness_conflicts = set()
        if native["native_form"]:
            nullable_columns = {column["name"] for column in native["native_form"]["columns"] if column["nullable"]}
            for element in module.iter():
                if _tag(element) not in {"item", "formitem"}: continue
                attributes = native_source._attrs(element)
                if attributes.get("required", "false").strip().lower() not in {"true", "yes"}: continue
                try:
                    column = native_source._identifier(attributes.get("columnname") or attributes.get("name", ""))
                except native_source._Unsupported:
                    continue
                if column in nullable_columns: requiredness_conflicts.add(column)
        form["findings"].extend(_native_finding(item, requiredness_conflicts=requiredness_conflicts) for item in native["blockers"]
                                if not ((table_ambiguous or rejected) and item["code"] == "DDL_REQUIRED"))
        form["native_form"] = deepcopy(native["native_form"])
        for element in module.iter():
            tag = _tag(element)
            if tag not in _DISPLAY_ONLY_OBJECTS and tag not in native_source._BLOCKING_OBJECTS and tag not in {"trigger", "programunit"}:
                form["findings"].append(_finding("UNMAPPED_FORMS_OBJECT", "UNSUPPORTED",
                    "This Forms object has no deterministic mapping in the declared profile.", name, tag))
        if form["native_form"]:
            for column in form["native_form"]["columns"]:
                if not _label(column["label"]):
                    form["findings"].append(_finding("COLUMN_LABEL_REVIEW_REQUIRED", "NEEDS_HUMAN",
                        "Provide a plain column label without APEX substitution strings.", name, column["name"]))
    if not modules:
        result["project_findings"].append(_finding("FORMS_REQUIRED", "MISSING_INPUT",
            "Add at least one readable Forms FormModule; supporting files alone cannot produce an application."))
    for view in result["source_files"]:
        view["module_ids"].sort()
        if view["disposition"] == "BLOCKED":
            continue
        if view["kind"] in {"SUPPORTING_SOURCE", "UNSUPPORTED_XML"}:
            view["disposition"] = "BLOCKED"
            result["project_findings"].append(_finding("UNCONVERTED_SUPPORTING_SOURCE", "NEEDS_HUMAN",
                "This selected supporting file has no deterministic conversion mapping. A dependency reference proves only source presence, not converted behavior.",
                view["name"], owner="SOURCE_OWNER",
                action="Clarify its required behavior and supply an explicit supported mapping, or change the selected source version; the original file remains retained."))
            continue
        if view["module_ids"]:
            view["disposition"] = "MAPPED"
        else:
            result["project_findings"].append(_finding("UNASSIGNED_SOURCE", "MISSING_INPUT" if not modules else "NEEDS_HUMAN",
                "This selected file is not mapped to a selected form. Explain its purpose or change the selected source set; the file is retained.",
                view["name"], owner="SOURCE_OWNER"))
    return _finish(result)


def module_execution_binding(plan: dict, *, parent_job_id: str, module_id: str) -> dict:
    """Derive one source-bound AI execution identity, not a child application.

    The caller must freshly compute ``plan`` from the complete selected source
    snapshot. A self-consistent supplied JSON plan is not source/authorization
    evidence. The converter owns the actual inspection inventory; FOX consumes
    that inventory after checking this binding rather than inventing its own.
    """
    def require(condition, code):
        if not condition:
            raise ProjectConversionInputError(code, "A complete current READY project plan is required for this module execution.")

    require(type(parent_job_id) is str and re.fullmatch(r"fox-[a-f0-9]{20}", parent_job_id), "PARENT_JOB_ID_INVALID")
    require(type(module_id) is str and re.fullmatch(r"form-[a-f0-9]{20}", module_id), "MODULE_ID_INVALID")
    require(type(plan) is dict and plan.get("schema_version") == 1 and type(plan.get("schema_version")) is int
            and plan.get("scope") == "fox-project-conversion-plan-v1" and plan.get("profile_id") == PROFILE_ID,
            "PROJECT_PLAN_INVALID")
    require(type(plan.get("plan_sha256")) is str and _SHA.fullmatch(plan["plan_sha256"])
            and _sha(_canonical({key: value for key, value in plan.items() if key != "plan_sha256"})) == plan["plan_sha256"],
            "PROJECT_PLAN_CHANGED")
    require(plan.get("state") == "READY" and plan.get("can_generate") is True
            and plan.get("assessment_complete") is True and plan.get("project_findings") == [],
            "PROJECT_NOT_READY")
    forms = plan.get("forms")
    require(type(forms) is list and 1 <= len(forms) <= MAX_FORMS
            and all(type(form) is dict and form.get("state") == "READY" and form.get("findings") == [] for form in forms),
            "PROJECT_NOT_READY")
    require(len({form["module_id"] for form in forms}) == len(forms), "MODULE_ID_COLLISION")
    selected = [form for form in forms if form["module_id"] == module_id]
    require(len(selected) == 1, "MODULE_NOT_IN_PROJECT")
    expected_spec = _rendering_spec(plan)
    require(plan.get("rendering_spec") == expected_spec, "PROJECT_RENDER_BINDING_CHANGED")
    mapped = expected_spec["schema_version"] == 2
    if mapped:
        source_files = plan.get("source_files")
        require(type(source_files) is list and all(type(source) is dict for source in source_files),
                "PROJECT_SOURCE_BINDING_CHANGED")
        sources = {source.get("name"): source for source in source_files}
        require(len(sources) == len(source_files)
            and {identity for source in source_files for identity in source.get("module_ids", [])}
                == {form["module_id"] for form in forms}
            and all(source.get("disposition") == "MAPPED" for source in source_files),
            "PROJECT_SOURCE_BINDING_CHANGED")
        manifest = "\n".join(source["name"] + ":" + source["sha256"]
                             for source in sorted(source_files, key=lambda source: source["name"]))
        require(_sha(manifest.encode("utf-8")) == plan["source_hash"], "PROJECT_SOURCE_BINDING_CHANGED")
        for candidate in forms:
            require(candidate.get("table_name") == candidate["storage_mapping"]["source_table_name"],
                    "PROJECT_SOURCE_BINDING_CHANGED")
            refs = [{"name": candidate["source_name"], "sha256": candidate["source_sha256"]},
                    *candidate["ddl_sources"]]
            require(all(ref["name"] in sources and sources[ref["name"]]["sha256"] == ref["sha256"]
                and candidate["module_id"] in sources[ref["name"]]["module_ids"] for ref in refs),
                "PROJECT_SOURCE_BINDING_CHANGED")
    form = selected[0]
    identity = {"scope": "fox-project-module-execution-v1", "parent_job_id": parent_job_id,
                "source_hash": plan["source_hash"], "module_id": module_id, "native_form": form["native_form"]}
    if mapped:
        identity.update(scope="fox-project-module-execution-v2", project_id=plan["project_id"],
                        plan_sha256=plan["plan_sha256"], storage_mapping=form["storage_mapping"],
                        ddl_sources=form["ddl_sources"])
    child = "fox-" + _sha(_canonical(identity))[:20]
    require(child != parent_job_id, "MODULE_EXECUTION_ID_COLLISION")
    binding = {"schema_version": 2 if mapped else 1, "scope": identity["scope"], "parent_job_id": parent_job_id,
            "child_job_id": child, "project_id": plan["project_id"], "module_id": module_id,
            "source_hash": plan["source_hash"], "plan_sha256": plan["plan_sha256"],
            "source_name": form["source_name"], "source_sha256": form["source_sha256"],
            "native_form_sha256": _sha(_canonical(form["native_form"]))}
    if mapped:
        binding.update(storage_mapping=deepcopy(form["storage_mapping"]), ddl_sources=deepcopy(form["ddl_sources"]))
    return binding
