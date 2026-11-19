"""Closed grammar and three-valued IR model tests, without Oracle execution."""
import pytest

from copy import deepcopy

from forms2apex.native_policy_rules import (parse_policy_text, UnsupportedPolicy, render_policy_code,
    derive_policy_operations, SCOPE, CODE_MEMBER, _canonical, _sha)


@pytest.mark.parametrize("text", ["", None, "X" * 16_385, ":X:=:Y;", "IF :X=1 THEN NULL; END IF;",
    "IF :X=1 THEN :Y:=2; ELSE :Y:=3; END IF;", "SET_BLOCK_PROPERTY('A.B',ENABLED,PROPERTY_TRUE);",
    "SET_ITEM_PROPERTY('A',VISIBLE,PROPERTY_TRUE);", "SET_ITEM_PROPERTY(:A,ENABLED,PROPERTY_TRUE);",
    "MESSAGE(:X);", "MESSAGE('x',NO_ACKNOWLEDGE);", "BEGIN MESSAGE('x'); END; COMMIT;",
    "BEGIN MESSAGE('x'); END OTHER;", "/* nested /* x */ MESSAGE('x');", "MESSAGE('unterminated);",
    "MESSAGE('&#10;');", "MESSAGE(q'[text]');", "MESSAGE('x'); &#65;", "PROCEDURE P(X NUMBER) IS BEGIN MESSAGE('x'); END;",
    "IF " + "NOT " * 30 + "FORM_SUCCESS THEN MESSAGE('x'); END IF;",
    "IF " + " OR ".join([":X=1"] * 100) + " THEN MESSAGE('x'); END IF;"])
def test_complete_parser_rejects_unsupported_or_unbounded_source(text):
    with pytest.raises(UnsupportedPolicy):
        parse_policy_text(text)


def test_quoted_comment_markers_stay_literals_and_encoded_newline_ends_comment():
    parsed, receipt = parse_policy_text("-- comment&#10;BEGIN MESSAGE('/* hi */ -- O''Brien'); END;&#13;")
    assert parsed["body"] == [{"kind": "warning", "message": "/* hi */ -- O'Brien"}]
    assert [row["codepoint"] for row in receipt["substitutions"]] == [10, 13]


@pytest.mark.parametrize("literal", ["NULL", "-1.25", "+3", "''", "'N'"])
def test_literal_assignments_and_optional_procedure_wrapper(literal):
    parsed, _ = parse_policy_text(f"PROCEDURE CHECK_RULE AS BEGIN IF :X<>:Y THEN :Z:={literal}; END IF; END CHECK_RULE;")
    assert parsed["procedure_name"] == "CHECK_RULE"
    assert parsed["body"][0]["body"][0]["kind"] == "assign"


def evaluate(node, values):
    """Independent source-AST model: Python truthiness must not stand in for NULL."""
    kind = node["kind"]
    if kind == "field": return values.get(".".join(node["parts"]))
    if kind == "intrinsic": return values.get(node["name"])
    if kind == "literal": return None if node["value"] == "" else node["value"]
    if kind in ("is_null", "is_not_null"):
        result = evaluate(node["value"], values) is None
        return result if kind == "is_null" else not result
    if kind == "not":
        value = evaluate(node["value"], values)
        return None if value is None else not value
    left, right = evaluate(node["left"], values), evaluate(node["right"], values)
    if kind == "and": return False if left is False or right is False else None if left is None or right is None else True
    if kind == "or": return True if left is True or right is True else None if left is None or right is None else False
    if left is None or right is None: return None
    return left == right if kind == "eq" else left != right


def effects(body, values, result):
    for node in body:
        kind = node["kind"]
        if kind == "if":
            if evaluate(node["condition"], values) is True and effects(node["body"], values, result):
                return True
        elif kind == "assign":
            values[".".join(node["target"]["parts"])] = evaluate(node["value"], values)
            result.append("assignment")
        elif kind == "failure":
            result.append("failure")
            return True
        elif kind == "property": result.append((node["property"], node["value"]))
        elif kind == "warning": result.append(("warning", node["message"]))
    return False


@pytest.mark.parametrize("a,b,expected", [(None,None,"unchanged"),("A",None,"unchanged"),(None,"A","unchanged"),
    ("A","B","unchanged"),("A","A","N")])
def test_no_else_assignment_preserves_previous_value_on_false_or_unknown(a,b,expected):
    parsed, _ = parse_policy_text("IF :A=:B THEN :DEST:='N'; END IF;")
    values, result = {"A": a, "B": b, "DEST": "unchanged"}, []
    effects(parsed["body"], values, result)
    assert values["DEST"] == expected


@pytest.mark.parametrize("value,expected", [(None,[True]),("N",[True]),("Y",[True,False])])
def test_resets_precede_conditional_overrides(value,expected):
    parsed, _ = parse_policy_text("SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_TRUE); IF :FLAG IS NOT NULL AND :FLAG='Y' THEN SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_FALSE); END IF;")
    result = []
    effects(parsed["body"], {"FLAG":value}, result)
    assert [value for _,value in result] == expected


@pytest.mark.parametrize("success,expected", [(True,[("warning","before"),("warning","after")]),
    (None,[("warning","before"),("warning","after")]), (False,[("warning","before"),"failure"])])
def test_form_success_not_null_semantics_and_failure_terminates(success,expected):
    parsed, _ = parse_policy_text("MESSAGE('before'); IF NOT(FORM_SUCCESS) THEN RAISE FORM_TRIGGER_FAILURE; END IF; MESSAGE('after');")
    result = []
    effects(parsed["body"], {"FORM_SUCCESS":success}, result)
    assert result == expected


@pytest.mark.parametrize("a,b,expected", [(True,None,True),(False,None,None),(None,None,None),(False,False,False)])
def test_or_preserves_three_valued_logic(a,b,expected):
    parsed, _ = parse_policy_text("IF FORM_SUCCESS OR :A='Y' THEN MESSAGE('x'); END IF;")
    assert evaluate(parsed["body"][0]["condition"], {"FORM_SUCCESS":a,"A":None if b is None else "Y" if b else "N"}) is expected


def standalone_plan(datatype="NUMBER"):
    """Synthetic closed catalog, with no FOX import or original/customer source."""
    def identity(number): return "ff1-" + f"{number:024x}"
    module, block, item, owner, unit = [identity(i) for i in range(1, 6)]
    text = "IF :VALUE IS NULL THEN :VALUE:=" + ("1" if datatype == "NUMBER" else "'N'") + "; END IF;"
    def obj(key, kind, name, parent, block_id=None, classification=None, metadata=None):
        return {"id": key, "kind": kind, "name": name, "parent_id": parent, "module_id": module,
                "block_id": block_id, "classification": classification,
                "database_item": True if kind == "Item" else None, "metadata": metadata or {"Name": name}}
    catalog = {"objects": [obj(module,"FormModule","DEMO",None),
        obj(block,"Block","ROWS",module,block,"database"),
        obj(item,"Item","VALUE",block,block, metadata={"Name":"VALUE", "DataType":datatype}),
        obj(owner,"Trigger","WHEN-NEW-RECORD-INSTANCE",block,block)], "units": [{
        "id":unit, "owner_id":owner,"source_attribute":"TriggerText", "sha256":_sha(text.encode()),
        "location":{"path":"/FormModule[1]/Block[1]/Trigger[1]","line":1,"column":1,"byte_offset":0},
        "chunk_id":"fup1-" + "b" * 64, "text":text}]}
    trace = {"source_binding":"a" * 64,"blocks":[{"source_block_id":block,"source_module_id":module,
        "name":"ROWS","classification":"database","items":[{"source_item_id":item,"source_name":"VALUE",
        "column":"C_VALUE","data_type":datatype,"database_bound":True,"value_computation_implemented":False}]}]}
    ops, coverage = derive_policy_operations(catalog, trace, trace["source_binding"])
    plan = {"schema_version":1,"scope":SCOPE,"source_binding":trace["source_binding"],
        "trace_sha256":_sha(_canonical(trace)),"parent_trace":trace,"source_catalog":catalog,
        "sources":[{"name":"demo.xml","sha256":"c" * 64,"bytes":512}],"operations":ops,"coverage":coverage,
        "code_unit_count":1,"native_generated":False,"event_activated":False,"runtime_verified":False,"business_accepted":False}
    plan["plan_sha256"] = _sha(_canonical(plan))
    return plan


@pytest.mark.parametrize("datatype", ["NUMBER", "VARCHAR2"])
def test_converter_standalone_typed_review_rendering_has_no_application_import(datatype):
    plan = standalone_plan(datatype)
    before = deepcopy(plan)
    sql, receipt = render_policy_code(plan)
    assert plan == before
    assert (sql, receipt) == render_policy_code(plan)
    assert f"p_f1 IN OUT {datatype}" in sql
    assert "IF (p_f1 IS NULL) THEN" in sql and " ELSE" not in sql
    assert "value := p_f1;" in sql
    assert "C_VALUE" not in sql and "WHEN-NEW-RECORD-INSTANCE" not in sql
    assert receipt["code_member"] == CODE_MEMBER
    assert receipt["converted_code_unit_count"] == 0
    assert receipt["generated_operations"][0]["encoding_status"] == "generated_unwired"


@pytest.mark.parametrize("mutation", ["unknown_ast", "different_owner", "different_module", "different_parent", "source_attribute",
    "unit_hash", "chunk_identity", "source_location", "decode_receipt", "source_type", "false_claim", "extra_catalog_key"])
def test_converter_rejects_resealed_catalog_or_ir_inconsistency(mutation):
    plan = standalone_plan()
    op = plan["operations"][0]
    catalog = plan["source_catalog"]
    if mutation == "unknown_ast": op["body"].append({"kind":"execute","sql":"COMMIT;"})
    if mutation == "different_owner": op["source_owner_id"] = "ff1-" + "0" * 24
    if mutation == "different_module": catalog["objects"][-1]["module_id"] = "ff1-" + "0" * 24
    if mutation == "different_parent": catalog["objects"][-1]["parent_id"] = "ff1-" + "0" * 24
    if mutation == "source_attribute": catalog["units"][0]["source_attribute"] = "Formula"
    if mutation == "unit_hash": catalog["units"][0]["sha256"] = "0" * 64
    if mutation == "chunk_identity": catalog["units"][0]["chunk_id"] = "invalid"
    if mutation == "source_location": catalog["units"][0]["location"]["line"] = 0
    if mutation == "decode_receipt": op["decode_receipt"]["semantic_sha256"] = "0" * 64
    if mutation == "source_type": catalog["objects"][-2]["metadata"]["DataType"] = "DATE"
    if mutation == "false_claim": plan["runtime_verified"] = True
    if mutation == "extra_catalog_key": catalog["sql"] = "COMMIT;"
    plan["plan_sha256"] = _sha(_canonical({k:v for k,v in plan.items() if k != "plan_sha256"}))
    with pytest.raises(ValueError): render_policy_code(plan)
