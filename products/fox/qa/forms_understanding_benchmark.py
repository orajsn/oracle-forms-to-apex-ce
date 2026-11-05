"""Public-authored synthetic benchmark inputs and non-semantic design scoring.

No provider calls, file writes, generation or execution. Only ``documents`` go
into production request building; expected_labels are evaluator-side metadata.
Free prose, a valid structure and lexical dependencies never prove behavior.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy

from fox.forms_focus_merge import merge_focus_blueprints
from fox.forms_understanding_packet import local_packet


def build_cases() -> list[dict]:
    """Return fresh, small Forms XML originals; no customer source is used."""
    definitions = [
        ("syn-order-dml", "SYN_ORDER_FORM", ' DatabaseBlock="true"',
         ' QueryDataSourceName="SYN_ORDERS"',
         [('SYN_ORDER_ID', 'true', 'Text Item'), ('SYN_STATUS', 'true', 'Text Item'),
          ('SYN_AMOUNT', 'true', 'Text Item')],
         '<Trigger Name="SYN_SAVE" TriggerText="BEGIN UPDATE SYN_ORDERS SET STATUS = \'READY\' '
         'WHERE ORDER_ID = :SYN_ORDERS.SYN_ORDER_ID; COMMIT_FORM; END;"/>',
         "database", ["SYN_ORDERS"]),
        ("syn-control-missing-package", "SYN_SEARCH_FORM", ' DatabaseBlock="false"', '',
         [('SYN_SEARCH_TEXT', 'false', 'Text Item'), ('SYN_SEARCH', 'false', 'Push Button')],
         '<Trigger Name="SYN_SEARCH_CLICK" TriggerText="BEGIN '
         "SYN_SEARCH_API.RUN_SEARCH(:SYN_FILTER.SYN_SEARCH_TEXT, 'OPEN'); END;\"/>",
         "control", ["SYN_SEARCH_API.RUN_SEARCH"]),
        ("syn-unknown-missing-body", "SYN_UNKNOWN_FORM", '', '',
         [('SYN_REFERENCE', None, 'Text Item'), ('SYN_VALUE', None, 'Text Item')],
         '<Trigger Name="SYN_VALIDATE"/>', "unknown", []),
    ]
    cases = []
    for case_id, module, flag, source, items, trigger, classification, candidates in definitions:
        block = {"database": "SYN_ORDERS", "control": "SYN_FILTER", "unknown": "SYN_UNCLASSIFIED"}[classification]
        parts = [f'<FormModule Name="{module}"><Block Name="{block}"{flag}{source}>']
        for name, database_item, item_type in items:
            item_flag = '' if database_item is None else f' DatabaseItem="{database_item}"'
            parts.append(f'<Item Name="{name}"{item_flag} ItemType="{item_type}"/>')
        parts.extend([trigger, '</Block></FormModule>'])
        cases.append({"case_id": case_id, "documents": [(case_id + '.xml', ''.join(parts).encode('utf-8'))],
                      "expected_labels": {"block_classification": classification,
                                          "candidate_dependency_names": candidates,
                                          "native_mapping_expected": classification != "unknown",
                                          "missing_trigger_body": classification == "unknown",
                                          "authorship": "public-authored-synthetic"}})
    return cases


def evaluate_case(case: dict, plan: dict, responses: list[dict]) -> dict:
    """Score exact production merge; no alternate response contract or repair.

    ``pass`` means expected safe proposal or safe abstention, not conversion or
    a correct business design. Unknown-block refusal can pass safety while
    receiving no useful-mapping credit. Question counts are only counts
    associated with missing-input owners, not proof the questions are useful.
    """
    report = {"case_id": case["case_id"], "structured_pass": False, "pass": False, "safety_case_pass": False,
              "accounted": 0, "proposed": 0, "omitted": 0, "unresolved": 0,
              "native_block_mapping_proposal_coverage": 0.0, "useful_design": False,
              "source_fact_counts": {"validated": 0}, "missing_input_questions_count": 0,
              "questions_count": 0, "safety_failure_issues": [],
              "expected_labels": deepcopy(case["expected_labels"]),
              "native_apex_generated": False, "native_apex_validity_verified": False,
              "business_behavior_accepted": False, "generation_ready": False,
              "semantic_correctness_verified": False,
              "evidence_level": "structured-source-bound-design-only"}
    try:
        result = merge_focus_blueprints(case["documents"], plan, responses)
    except ValueError as error:
        report["safety_failure_issues"] = [str(error)]
        return report
    packet = local_packet(case["documents"])
    facts = [entry["facts"] for entry in packet["sources"]]
    objects = {row["id"]: row for fact in facts for row in fact["objects"]}
    blueprint, validation = result["blueprint"], result["validation"]
    report.update(structured_pass=True, accounted=validation["accounted_objects"],
                  proposed=validation["proposed_objects"], omitted=validation["omitted_objects"],
                  unresolved=validation["unresolved_objects"])
    claims = Counter(claim["kind"] for claim in blueprint["claims"] if claim["status"] == "source_fact")
    report["source_fact_counts"] = {"validated": validation["source_fact_claims"], "by_kind": dict(sorted(claims.items()))}
    dispositions = {row["source_object_id"]: row for row in blueprint["objects"]}
    blocks = [row for row in objects.values() if row["kind"] == "Block"]
    mapped = sum(dispositions[row["id"]]["disposition"] == "proposed" for row in blocks)
    report["native_block_mapping_proposal_coverage"] = mapped / len(blocks) if blocks else 0.0
    report["useful_design"] = bool(mapped)
    dependency_names = sorted({row["name"] for fact in facts for row in fact["dependencies"]})
    report["observed_candidate_dependency_names"] = dependency_names
    report["expected_candidate_names_retained"] = all(
        name in dependency_names for name in case["expected_labels"]["candidate_dependency_names"])
    # Metadata association only. No keyword matching of free prose is credited.
    unit_owners = {unit["owner_id"] for fact in facts for unit in fact["code_units"]}
    missing_owners = {row["id"] for row in objects.values()
                      if (row["kind"] in {"Trigger", "ProgramUnit"} and row["id"] not in unit_owners)
                      or (row["kind"] == "Block" and row["classification"] == "unknown")}
    missing_owners.update(row["source_id"] for fact in facts for row in fact["dependencies"])
    report["questions_count"] = len(blueprint["questions"])
    report["missing_input_questions_count"] = sum(
        row["source_object_id"] in missing_owners for row in blueprint["questions"])
    report["safety_case_pass"] = not report["safety_failure_issues"]
    report["pass"] = report["safety_case_pass"] and (
        report["useful_design"] if case["expected_labels"]["native_mapping_expected"]
        else not report["useful_design"])
    return report
