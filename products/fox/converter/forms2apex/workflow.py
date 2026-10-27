from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import shutil
import urllib.error
import urllib.request
import zipfile
import threading
import uuid
import re
from datetime import datetime, timezone
from functools import wraps

from .config import Settings
from .forms_inventory import inspect_intake
from .job_store import JobStore
from .security import assert_safe_generated_content, safe_relative_path
from .sqlcl import import_apexlang, import_apexlang_durable, reconcile_apexlang_import, validate_apexlang
from .starter import TEMPLATE_ID, template_context, merge_template, render_prototype_html
from .release import runtime_login_check
from .provenance import tree_digest, inspection_binding, draft_binding, draft_snapshot
from .native import TEMPLATE_ID as NATIVE_TEMPLATE_ID, context as native_context, render_native_form
from .review_receipts import verify_review

_NATIVE_CANDIDATE_FIELDS={'job_id','template_id','data_classification','generator','native_form','remediation_items','mapping_summary'}


# This service is a single-process MVP. Serialize managed writes and SQLcl
# handoffs; separate worker processes require a durable lock before deployment.
_WORKFLOW_LOCK = threading.RLock()


def serialized(method):
    @wraps(method)
    def wrapped(*args, **kwargs):
        with _WORKFLOW_LOCK:
            return method(*args, **kwargs)
    return wrapped


class ConverterWorkflow:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = JobStore(settings.jobs_root)

    def review_identity(self):
        return (self.settings.opaf_mapper_workflow_id,self.settings.opaf_reviewer_workflow_id,
                self.settings.generator_model,self.settings.reviewer_model)

    def target_profile(self):
        from .runtime_preflight import bound_target_profile
        return bound_target_profile(self.settings)

    def review_target_profile(self):
        # Old sealed v1 receipts remain verifiable without inventing environment
        # observations. V2 requires its configured local profile, never live OPAF.
        return self.target_profile() if self.settings.target_profile_path is not None else None

    def verify_native_review(self,root,spec):
        candidate={key:spec[key] for key in _NATIVE_CANDIDATE_FIELDS if key in spec}
        # V2 carries its registered historical profile; v1 keeps its original
        # identity-only proof. Neither verification reads today's target file
        # or requires OPAF to be online. Creation/fresh target actions are gated
        # separately and must not reinterpret retained artifact evidence.
        return verify_review(root,candidate,*self.review_identity())

    def native_target_preflight(self,job_id,action):
        """Fresh deterministic checks plus durable local evidence; no model call."""
        from .runtime_preflight import collect_deterministic_preflight
        root=self.store.require(job_id)
        binding=self.assert_artifact_binding(job_id)  # Includes historical review.
        spec=json.loads((root/'migration-spec.json').read_text(encoding='utf-8'))
        if spec.get('template_id')!=NATIVE_TEMPLATE_ID:
            raise RuntimeError('Native target preflight requires a native reviewed job')
        manifest=json.loads((root/'intake/manifest.json').read_text(encoding='utf-8-sig'))
        receipt=collect_deterministic_preflight(self.settings,root,job_id=job_id,action=action,
            source_manifest_sha256=manifest.get('source_manifest_sha256'))
        if self.assert_artifact_binding(job_id)!=binding:
            raise RuntimeError('Artifact changed during target preflight')
        record={'schema_version':1,'artifact_binding':binding,'preflight':receipt}
        raw=json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
        name='target-check-'+action+'-'+uuid.uuid4().hex[:16]+'.json'
        with (root/name).open('xb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        if os.name!='nt':
            descriptor=os.open(root,os.O_RDONLY)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        return {'file':name,'sha256':hashlib.sha256(raw).hexdigest(),'action':action,
                'profile_sha256':receipt['profile_sha256'],'receipt_sha256':receipt['receipt_sha256']}

    def assert_native_preflight_fresh(self,job_id,reference,action):
        from .runtime_preflight import verify_action_preflight
        root=self.store.require(job_id)
        if not isinstance(reference,dict) or reference.get('action')!=action:
            raise RuntimeError('Native target preflight action binding is missing')
        name=reference.get('file')
        if not isinstance(name,str) or not re.fullmatch(r'target-check-'+re.escape(action)+r'-[a-f0-9]{16}\.json',name):
            raise RuntimeError('Native target preflight path is invalid')
        path=root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:
            raise RuntimeError('Native target preflight evidence is unavailable')
        raw=path.read_bytes()
        if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=reference.get('sha256'):
            raise RuntimeError('Native target preflight evidence changed')
        record=json.loads(raw)
        if (not isinstance(record,dict) or set(record)!={'schema_version','artifact_binding','preflight'}
                or type(record['schema_version']) is not int or record['schema_version']!=1
                or record['artifact_binding']!=self.assert_artifact_binding(job_id)):
            raise RuntimeError('Native target preflight is not bound to the current artifact')
        profile=self.target_profile()
        manifest=json.loads((root/'intake/manifest.json').read_text(encoding='utf-8-sig'))
        checked=verify_action_preflight(record['preflight'],profile,job_id=job_id,action=action,
            source_manifest_sha256=manifest.get('source_manifest_sha256'),now=datetime.now(timezone.utc))
        if checked['receipt_sha256']!=reference.get('receipt_sha256') or checked['profile_sha256']!=reference.get('profile_sha256'):
            raise RuntimeError('Native target preflight reference changed')

    @serialized
    def inspect(self, job_id: str) -> dict:
        root = self.store.require(job_id)
        if self.store.read(job_id)['state'] not in {'INTAKE_READY','INSPECTED','FAILED'}:
            raise RuntimeError('Inspection is blocked after draft materialization')
        if (root/'import-intent.json').exists():
            raise RuntimeError('An import intent exists; reconcile the existing job instead of reinspecting')
        intake_before = tree_digest(root/'intake')
        inventory = inspect_intake(root)
        if tree_digest(root/'intake') != intake_before:
            raise RuntimeError('Source changed during inspection')
        inventory['apex_starter'] = template_context()
        inventory['native_apex_profile'] = native_context()
        manifest=json.loads((root/'intake/manifest.json').read_text(encoding='utf-8-sig'))
        if manifest.get('native_form') is not None:
            inventory['approved_native_form']=manifest['native_form']
        inventory_path = root / "normalized-forms-inventory.json"
        inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report = {
            "job_id": job_id,
            "remediation_items": inventory["remediation_items"],
            "unsupported_count": len(inventory["remediation_items"]),
            "production_database_connected": False,
            "data_policy": "Inferred stub tables and synthetic data only.",
        }
        (root / "migration-and-exception-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        binding = inspection_binding(root)
        if binding['intake_sha256'] != intake_before:
            raise RuntimeError('Source changed during inspection')
        self.store.transition(job_id, "INSPECTED", {"inventory": str(inventory_path), 'inspection_binding':binding})
        return inventory

    @serialized
    def generate(self, job_id: str, migration_spec: str) -> dict:
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] not in {"INSPECTED", "INVALID", "VALID", "FAILED"}:
            raise RuntimeError("job must be inspected before a draft can be materialized")
        if (root/'import-intent.json').exists():
            raise RuntimeError('An import intent exists; reconcile the existing job before regeneration')
        if not status.get('inspection_binding') or inspection_binding(root) != status['inspection_binding']:
            raise RuntimeError('Source or inspection evidence changed; inspect a new job before generation')
        spec = json.loads(migration_spec)
        if spec.get("data_classification") != "synthetic_or_stub_only":
            raise ValueError("migration_spec.data_classification must be synthetic_or_stub_only")
        if spec.get("generator", {}).get("model") != self.settings.generator_model:
            raise ValueError(f"generator model must be {self.settings.generator_model}")
        native=spec.get('template_id')==NATIVE_TEMPLATE_ID
        if not native:
            reviewer = spec.get("reviewer", {})
            if reviewer.get("model") != self.settings.reviewer_model or reviewer.get("verdict") != "approve":
                raise ValueError(f"independent {self.settings.reviewer_model} approval is required")
        if spec.get('template_id') not in {TEMPLATE_ID,NATIVE_TEMPLATE_ID}:
            raise ValueError('The canonical template_id is required for this conversion profile')
        if spec['template_id']==NATIVE_TEMPLATE_ID:
            if 'prototype_html' in spec or 'apexlang_files' in spec:
                raise ValueError('Native generation accepts field metadata only, not HTML or APEXlang')
            if set(spec)!=_NATIVE_CANDIDATE_FIELDS:
                raise ValueError('Native candidate must contain only the approved metadata envelope; reviewer evidence is separate')
            receipt=self.verify_native_review(root,spec)
            spec['reviewer']={'model':self.settings.reviewer_model,'verdict':'approve','notes':receipt['review']['notes'],
                              'receipt_sha256':receipt['receipt_sha256'],'room_id':receipt['reviewer_invocation']['room_id']}
            assert_safe_generated_content(json.dumps(spec.get('native_form')), 'native-spec.txt')
            files=render_native_form(spec.get('native_form'))
        else:
            manifest=json.loads((root/'intake/manifest.json').read_text(encoding='utf-8-sig'))
            if manifest.get('native_form') is not None:
                raise ValueError('A native job cannot fall back to the HTML prototype')
            if 'native_form' in spec:
                raise ValueError('Native field metadata requires the native template')
            files = spec.get("apexlang_files")
            if 'prototype_html' in spec:
                if files:
                    raise ValueError('Use prototype_html or apexlang_files, not both')
                files = render_prototype_html(spec.get('template_id'), spec['prototype_html'])
            if not isinstance(files, dict) or not files:
                raise ValueError("migration_spec.apexlang_files must be a non-empty object")
            # Scan model content before merging trusted, SQLcl-generated login scaffolding.
            for relative, content in files.items():
                safe_relative_path(relative)
                if not isinstance(content, str):
                    raise ValueError('Draft content must be text')
                assert_safe_generated_content(content, relative)
            files = merge_template(spec['template_id'], files)

        inventory_path = root / "normalized-forms-inventory.json"
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        required = {
            (item.get("file"), item.get("kind"))
            for item in inventory.get("remediation_items", [])
        }
        supplied_items = spec.get("remediation_items", [])
        if not isinstance(supplied_items, list):
            raise ValueError("migration_spec.remediation_items must be an array")
        supplied = {
            (item.get("file"), item.get("kind"))
            for item in supplied_items
            if isinstance(item, dict)
        }
        missing = sorted(required - supplied)
        if missing:
            raise ValueError(f"migration_spec omitted required remediation items: {missing}")

        draft = root / "apexlang"
        temporary = root / ".apexlang-new"
        if temporary.exists():
            shutil.rmtree(temporary)
        temporary.mkdir()
        try:
            for relative, content in files.items():
                safe = safe_relative_path(relative)
                if not isinstance(content, str):
                    raise ValueError(f"draft content must be text: {relative}")
                target = temporary.joinpath(*safe.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", newline="\n")
            if draft.exists():
                shutil.rmtree(draft)
            temporary.replace(draft)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

        spec_path = root / "migration-spec.json"
        safe_spec = dict(spec)
        # Preserve the submitted reviewed content, not just a list of filenames.
        # It is customer source evidence and stays within the protected job.
        safe_spec['materialized_files'] = sorted(files)
        spec_path.write_text(json.dumps(safe_spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        zip_path = root / f"{job_id}-apexlang.zip"
        zip_path.unlink(missing_ok=True)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(draft.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(draft).as_posix())
        if inspection_binding(root) != status['inspection_binding']:
            raise RuntimeError('Source or inspection evidence changed during generation')
        binding = draft_binding(root)
        self.store.transition(job_id, "DRAFTED", {"apexlang_zip": str(zip_path), "validation": None, 'artifact_binding':binding})
        return {"job_id": job_id, "draft": str(draft), "zip": str(zip_path), "files": len(files)}

    def assert_artifact_binding(self, job_id: str) -> dict:
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        expected = status.get('artifact_binding')
        if not expected or draft_binding(root) != expected:
            raise RuntimeError('Artifact evidence changed or is unbound; validation/import/release is blocked')
        if expected['template_id']==NATIVE_TEMPLATE_ID:
            self.verify_native_review(root,json.loads((root/'migration-spec.json').read_text(encoding='utf-8')))
        if status['state'] in {'VALID','IMPORTED'} and status.get('validation',{}).get('artifact_binding') != expected:
            raise RuntimeError('Validation is not bound to this artifact; import/release is blocked')
        if status['state'] == 'IMPORTED':
            imported = json.loads((root/'imported-application.json').read_text(encoding='utf-8'))
            receipt = status.get('import',{})
            keys = ('artifact_binding','application_id','application_alias','workspace')
            if imported.get('artifact_binding') != expected or any(imported.get(k)!=receipt.get(k) for k in keys):
                raise RuntimeError('Imported application receipt changed; release is blocked')
            if expected['template_id']==NATIVE_TEMPLATE_ID and imported!=receipt:
                raise RuntimeError('Native import completion evidence differs from the committed job state')
        return expected

    @serialized
    def validate(self, job_id: str) -> dict:
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] != "DRAFTED":
            raise RuntimeError("only a newly drafted job can be validated")
        binding = self.assert_artifact_binding(job_id)
        spec=json.loads((root/'migration-spec.json').read_text(encoding='utf-8'))
        preflight=self.native_target_preflight(job_id,'validate') if spec.get('template_id')==NATIVE_TEMPLATE_ID else None
        with draft_snapshot(root,binding['draft_sha256']) as snapshot:
            result = validate_apexlang(self.settings.sqlcl_path, snapshot, root / "validation-results.log")
            try:
                self.assert_artifact_binding(job_id)
                if tree_digest(snapshot) != binding['draft_sha256']:
                    raise RuntimeError('Validation snapshot changed')
            except RuntimeError:
                result.update(passed=False, summary='Artifact changed during validation; regenerate and revalidate.')
        result['artifact_binding'] = binding
        if preflight is not None:result['target_preflight']=preflight
        result["job_id"] = job_id
        new_state = "VALID" if result["passed"] else "INVALID"
        self.store.transition(job_id, new_state, {"validation": result})
        return result

    @serialized
    def import_draft(self, job_id: str) -> dict:
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] != "VALID" or not status.get("validation", {}).get("passed"):
            raise RuntimeError("import is blocked unless the latest deterministic SQLcl validation passed")
        if not self.settings.apex_base_url.startswith("https://"):
            raise RuntimeError("F2A_APEX_BASE_URL must be an HTTPS ORDS base URL before import")
        binding = self.assert_artifact_binding(job_id)
        intent = root/'import-intent.json'
        if intent.exists():
            raise RuntimeError('A previous import attempt needs reconciliation; automatic replay is blocked')
        spec=json.loads((root/'migration-spec.json').read_text(encoding='utf-8'))
        native_schema=None
        preflight=None
        if spec['template_id']==NATIVE_TEMPLATE_ID:
            from .native_target import verify_native_schema
            native_schema=verify_native_schema(self.settings,spec['native_form'],root)
            preflight=self.native_target_preflight(job_id,'import')
        with draft_snapshot(root,binding['draft_sha256']) as snapshot:
            intent.write_text(json.dumps({'job_id':job_id,'workspace':self.settings.apex_workspace,'artifact_binding':binding},sort_keys=True),encoding='utf-8')
            try:
                arguments=(self.settings.sqlcl_path,self.settings.sqlcl_connection_name,
                           self.settings.apex_workspace,job_id,snapshot,root/'import.log')
                if native_schema is not None:
                    result=import_apexlang_durable(*arguments,intent_path=root/'sqlcl-import-intent.json',
                        expected_draft_sha256=binding['draft_sha256'],artifact_binding=binding,
                        pre_write_check=lambda:self.assert_native_preflight_fresh(job_id,preflight,'import'))
                else:
                    result=import_apexlang(*arguments)
            except Exception:
                self.store.transition(job_id,'FAILED',{'import_reconciliation_required':True})
                raise
            try:
                self.assert_artifact_binding(job_id)
                if tree_digest(snapshot) != binding['draft_sha256']:
                    raise RuntimeError('Import snapshot changed')
            except RuntimeError:
                self.store.transition(job_id,'FAILED',{'import_reconciliation_required':True})
                raise RuntimeError('Artifact changed during import; reconcile the target before any retry') from None
        result['artifact_binding'] = binding
        if native_schema is not None:
            result['native_schema_verification']=native_schema
            result['target_preflight']=preflight
            result['parsing_schema']=self.settings.apex_parsing_schema
        result["job_id"] = job_id
        result["application_url"] = (
            f"{self.settings.apex_base_url}/r/{self.settings.apex_workspace.lower()}/"
            f"{result['application_alias'].lower()}/"
        )
        (root / "imported-application.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        smoke = runtime_login_check(result['application_url'])
        (root / "smoke-test-report.json").write_text(
            json.dumps(smoke, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.store.transition(job_id, "IMPORTED", {"import": result, "smoke_test": smoke})
        result["smoke_test"] = smoke
        return result

    def status(self, job_id: str) -> dict:
        return self.store.read(job_id)

    @serialized
    def reconcile_import(self,job_id: str) -> dict:
        """Recover a confirmed native import using only read-only target proof.

        A true timeout without the SQLcl completion receipt remains blocked.
        No import command, regeneration or application replacement occurs here.
        """
        root=self.store.require(job_id)
        status=self.store.read(job_id)
        if not self.settings.apex_base_url.startswith('https://'):
            raise RuntimeError('F2A_APEX_BASE_URL must be HTTPS before recovery')
        if status['state'] not in {'VALID','FAILED'} or not (root/'import-intent.json').is_file():
            raise RuntimeError('No recoverable import intent exists')
        binding=self.assert_artifact_binding(job_id)
        validation=status.get('validation')
        if not isinstance(validation,dict) or validation.get('passed') is not True or validation.get('artifact_binding')!=binding:
            raise RuntimeError('Import recovery requires unchanged successful validation')
        spec=json.loads((root/'migration-spec.json').read_text(encoding='utf-8'))
        if spec.get('template_id')!=NATIVE_TEMPLATE_ID:
            raise RuntimeError('Only native imports with durable completion receipts can be reconciled')
        intent=json.loads((root/'import-intent.json').read_text(encoding='utf-8'))
        if intent!={'job_id':job_id,'workspace':self.settings.apex_workspace,'artifact_binding':binding}:
            raise RuntimeError('Import intent changed; recovery blocked')
        from .native_target import verify_native_schema
        native_schema=verify_native_schema(self.settings,spec['native_form'],root)
        preflight=self.native_target_preflight(job_id,'reconcile')
        result=reconcile_apexlang_import(self.settings.sqlcl_path,self.settings.sqlcl_connection_name,
            self.settings.apex_workspace,job_id,root/'apexlang',root/'import-reconciliation.log',
            intent_path=root/'sqlcl-import-intent.json',expected_draft_sha256=binding['draft_sha256'],artifact_binding=binding)
        if self.assert_artifact_binding(job_id)!=binding:
            raise RuntimeError('Artifact changed during read-only import reconciliation')
        after=self.store.read(job_id)
        if after['state']!=status['state'] or after.get('validation')!=status.get('validation'):
            raise RuntimeError('Validation or state changed during read-only import reconciliation')
        if (result.get('reconciled') is not True or result.get('target_writes') is not False
                or result.get('reconciliation_scope')!='exact_identity_and_complete_compiled_metadata'):
            raise RuntimeError('Read-only recovery proof is required')
        result.update(job_id=job_id,artifact_binding=binding,native_schema_verification=native_schema,
                      target_preflight=preflight,parsing_schema=self.settings.apex_parsing_schema)
        result['application_url']=(f'{self.settings.apex_base_url}/r/{self.settings.apex_workspace.lower()}/'
                                   f"{result['application_alias'].lower()}/")
        receipt=root/'imported-application.json'
        if receipt.exists():
            saved=json.loads(receipt.read_text(encoding='utf-8'))
            if any(saved.get(k)!=result.get(k) for k in ('job_id','artifact_binding','application_id','application_alias','workspace','application_url','import_intent_sha256','compiled_metadata_sha256')):
                raise RuntimeError('Existing imported application receipt differs; preserved for review')
            previous_schema=saved.get('native_schema_verification',{})
            if not isinstance(previous_schema,dict) or ({k:v for k,v in previous_schema.items() if k!='verified_at_utc'}
                    != {k:v for k,v in native_schema.items() if k!='verified_at_utc'}):
                raise RuntimeError('Existing native schema proof differs; preserved for review')
            # Preserve original successful receipt; keep fresh recovery proof separately.
            imported=saved
        else:
            from .release import _atomic_json
            _atomic_json(receipt,result)
            imported=result
        from .release import _atomic_json
        _atomic_json(root/'import-recovery.json',result)
        smoke=runtime_login_check(result['application_url'])
        _atomic_json(root/'smoke-test-report.json',smoke)
        self.store.transition(job_id,'IMPORTED',{'import':imported,'smoke_test':smoke,
            'import_reconciliation_required':False,'import_recovery':result})
        return {**imported,'recovery':result,'smoke_test':smoke}
