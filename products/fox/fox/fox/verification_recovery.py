"""Inert, explicit recovery records; never imported by the current runtime.

A closed failure is not a successful verification or an application RCA.
Original queue rows and artifacts remain immutable. A separately authorized
retry has a new identity and release; nothing here runs or promotes that retry.
Only protected integration may supply the authoritative producer probe.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import sqlite3
import types
import zipfile

from .verification_queue import Claim, VerificationBinding, VerificationQueue, TechnicalProofResult
from .native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt, INSTANCE, POLICY_ID
from .native_qa_plan import derive_native_qa_plan, derive_native_qa_profile, qa_plan_sha256
from .native_pipeline import verify_package
from .intake import checked_source, inventory, MAX_CONVERSION_BYTES

_SHA = re.compile(r'[a-f0-9]{64}\Z')
_SESSION = re.compile(r'session-[a-f0-9]{24}\Z')
_QA_RUN = re.compile(r'FQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}\Z')
_ATTEMPT = re.compile(r'attempt-[a-f0-9]{32}\Z')
_REQUEST = re.compile(r'request-[a-f0-9]{32}\Z')
PHASES = ('prepare', 'clean_check', 'allocate', 'schema', 'import', 'verify',
          'qa_stage', 'qa_run', 'qa_collect')
FILES = frozenset({'package.zip', 'native-form-spec.json', 'allocation-receipt.json',
    'verification-profile.json', 'clean-import-receipt.json', 'qa-profile.json',
    'target-receipt.json', 'qa-result.json', 'stage-receipt.json', 'launch-intent.json',
    'dispatch-receipt.json', 'launch-receipt.json'})
DISPOSITION_SCOPE = 'fox-verification-failed-disposition-v1'
RETRY_SCOPE = 'fox-verification-retry-request-v1'
_PRODUCER_KEYS = {'schema_version', 'scope', 'binding_sha256', 'session_id', 'qa_run_id',
    'container_id', 'image_id', 'state', 'exit_code', 'observed_at_utc',
    'live_producer_count', 'unresolved_phase_count', 'technical_proof_count', 'human_acceptance_count'}
SYNCHRONOUS_SCOPE = 'fox-verification-synchronous-launch-observation-v1'
SYNCHRONOUS_INVENTORY_SCOPE = 'fox-verification-synchronous-launch-observation-v2'
TIMESTAMPED_SYNCHRONOUS_SCOPE = SYNCHRONOUS_INVENTORY_SCOPE
CLASSIFICATION_CONTRACT_SHA256 = '2e2e1d9af82be6630d461e516464e8d179ac05de01bc2f6cedda77cc4f948875'
_CLASSIFICATION_SOURCE_B64 = 'IiIiUHVyZSB0aW1lc3RhbXBlZCBRQS1wcm9kdWNlciBjbGFzc2lmaWNhdGlvbiwgc2hhcmVkIGJ5IGhvc3QgYW5kIHZhbGlkYXRvcnMuCgpQeXRob24gMy42IGNvbXBhdGlibGUuIE5vIEkvTywgcnVudGltZSBkaXNjb3ZlcnksIGNhbGxlci1hdXRob3JpemVkIGV4Y2VwdGlvbnMsCmNvbnRhaW5lciBtdXRhdGlvbiwgb3IgY29udmVyc2lvbi9yZWNvdmVyeSBhdXRob3JpdHkuIFJhdyBjb250YWluZXIgc3RhdHVzIGlzCm5ldmVyIHJld3JpdHRlbjogQ1JFQVRFRF9ORVZFUl9TVEFSVEVEIGlzIGRpc3RpbmN0IGZyb20gU1RPUFBFRF9OT05fTElWRS4KIiIiCmltcG9ydCBjYWxlbmRhcgpmcm9tIGRhdGV0aW1lIGltcG9ydCBkYXRldGltZQpmcm9tIGRlY2ltYWwgaW1wb3J0IERlY2ltYWwKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGpzb24KaW1wb3J0IHJlCgpTQ09QRSA9ICdmb3gtdGltZXN0YW1wZWQtcHJvZHVjZXItaW52ZW50b3J5LXdpdG5lc3MtdjEnClJPV19LRVlTID0gZnJvemVuc2V0KCgnaWQnLCAnbmFtZScsICdpbWFnZScsICdzdGF0dXMnLCAncnVubmluZycsICdwaWQnLCAnZXhpdF9jb2RlJywKICAgICAgICAgICAgICAgICAgICAgICdjcmVhdGVkX2F0JywgJ3N0YXJ0ZWRfYXQnLCAnZmluaXNoZWRfYXQnKSkKU05BUFNIT1RfS0VZUyA9IGZyb3plbnNldCgoJ29ic2VydmVkX2F0X3V0YycsICdyb290bGVzc19jb250YWluZXJfY291bnQnLCAncm9vdGxlc3NfaW52ZW50b3J5X3NoYTI1NicsICdwcm9kdWNlcnMnKSkKU1RBVEVTID0gZnJvemVuc2V0KCgnY3JlYXRlZCcsICdydW5uaW5nJywgJ3BhdXNlZCcsICdyZXN0YXJ0aW5nJywgJ3N0b3BwaW5nJywgJ3N0b3BwZWQnLCAnZXhpdGVkJywgJ2NvbmZpZ3VyZWQnLCAnaW5pdGlhbGl6ZWQnLCAndW5rbm93bicpKQpDTEFTU0lGSUNBVElPTlMgPSBmcm96ZW5zZXQoKCdDUkVBVEVEX05FVkVSX1NUQVJURUQnLCAnU1RPUFBFRF9OT05fTElWRScsICdMSVZFJywgJ1VOS05PV04nKSkKTUFYX1JPT1RMRVNTID0gMjU2Ck1BWF9SRUxFVkFOVCA9IDY0Ck1BWF9XSVRORVNTX0JZVEVTID0gNDhfMDAwClpFUk8gPSAnMDAwMS0wMS0wMVQwMDowMDowMFonCgoKY2xhc3MgSW52ZW50b3J5Q29udHJhY3RFcnJvcihWYWx1ZUVycm9yKToKICAgIHBhc3MKCgpkZWYgbmVlZChvaywgY29kZSk6CiAgICBpZiBub3Qgb2s6CiAgICAgICAgcmFpc2UgSW52ZW50b3J5Q29udHJhY3RFcnJvcihjb2RlKQoKCmRlZiBkaWdlc3QodmFsdWUpOgogICAgcmV0dXJuIHR5cGUodmFsdWUpIGlzIHN0ciBhbmQgcmUuZnVsbG1hdGNoKCdbYS1mMC05XXs2NH0nLCB2YWx1ZSkgaXMgbm90IE5vbmUKCgpkZWYgY2Fub25pY2FsKHZhbHVlKToKICAgIHRyeToKICAgICAgICByZXR1cm4gKGpzb24uZHVtcHModmFsdWUsIHNvcnRfa2V5cz1UcnVlLCBzZXBhcmF0b3JzPSgnLCcsICc6JyksIGVuc3VyZV9hc2NpaT1GYWxzZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYWxsb3dfbmFuPUZhbHNlKSArICdcbicpLmVuY29kZSgndXRmLTgnKQogICAgZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVlRXJyb3IsIFVuaWNvZGVFcnJvciwgUmVjdXJzaW9uRXJyb3IpOgogICAgICAgIHJhaXNlIEludmVudG9yeUNvbnRyYWN0RXJyb3IoJ0lOVkVOVE9SWV9KU09OX0lOVkFMSUQnKSBmcm9tIE5vbmUKCgpkZWYgdGltZXN0YW1wKHZhbHVlKToKICAgIG5lZWQodHlwZSh2YWx1ZSkgaXMgc3RyLCAnSU5WRU5UT1JZX1VUQ19JTlZBTElEJykKICAgIG1hdGNoID0gcmUuZnVsbG1hdGNoKHInKFxkezR9LVxkezJ9LVxkezJ9VFxkezJ9OlxkezJ9OlxkezJ9KSg/OlwuKFxkezEsOX0pKT8oPzpafFwrMDA6MDApJywgdmFsdWUpCiAgICBuZWVkKG1hdGNoIGlzIG5vdCBOb25lLCAnSU5WRU5UT1JZX1VUQ19JTlZBTElEJykKICAgIHRyeToKICAgICAgICB3aG9sZSA9IGNhbGVuZGFyLnRpbWVnbShkYXRldGltZS5zdHJwdGltZShtYXRjaC5ncm91cCgxKSwgJyVZLSVtLSVkVCVIOiVNOiVTJykudGltZXR1cGxlKCkpCiAgICBleGNlcHQgKFZhbHVlRXJyb3IsIE92ZXJmbG93RXJyb3IpOgogICAgICAgIHJhaXNlIEludmVudG9yeUNvbnRyYWN0RXJyb3IoJ0lOVkVOVE9SWV9VVENfSU5WQUxJRCcpIGZyb20gTm9uZQogICAgcmV0dXJuIERlY2ltYWwod2hvbGUpICsgRGVjaW1hbCgnMC4nICsgKG1hdGNoLmdyb3VwKDIpIG9yICcwJykpCgoKZGVmIGNsYXNzaWZ5X3Jvdyhyb3csIG9ic2VydmVkX2F0X3V0Yyk6CiAgICAiIiJEZXJpdmUgc3RhdGUgZnJvbSBjb21wbGV0ZSBtZWFzdXJlZCBtZXRhZGF0YSwgbmV2ZXIgYW4gSUQvbmFtZSBleGVtcHRpb24uIiIiCiAgICBuZWVkKHR5cGUocm93KSBpcyBkaWN0IGFuZCBzZXQocm93KSA9PSBST1dfS0VZUywgJ0lOVkVOVE9SWV9ST1dfRklFTERTX0lOVkFMSUQnKQogICAgbmVlZChkaWdlc3Qocm93WydpZCddKSBhbmQgdHlwZShyb3dbJ25hbWUnXSkgaXMgc3RyCiAgICAgICAgIGFuZCByZS5mdWxsbWF0Y2goJ1tBLVphLXowLTldW0EtWmEtejAtOV8uLV17MCwxMjd9Jywgcm93WyduYW1lJ10pCiAgICAgICAgIGFuZCB0eXBlKHJvd1snaW1hZ2UnXSkgaXMgc3RyIGFuZCByZS5mdWxsbWF0Y2goJ3NoYTI1NjpbYS1mMC05XXs2NH0nLCByb3dbJ2ltYWdlJ10pCiAgICAgICAgIGFuZCB0eXBlKHJvd1snc3RhdHVzJ10pIGlzIHN0ciBhbmQgcm93WydzdGF0dXMnXSBpbiBTVEFURVMKICAgICAgICAgYW5kIHR5cGUocm93WydydW5uaW5nJ10pIGlzIGJvb2wgYW5kIHR5cGUocm93WydwaWQnXSkgaXMgaW50IGFuZCAwIDw9IHJvd1sncGlkJ10gPD0gMiAqKiAzMSAtIDEKICAgICAgICAgYW5kIHR5cGUocm93WydleGl0X2NvZGUnXSkgaXMgaW50IGFuZCAwIDw9IHJvd1snZXhpdF9jb2RlJ10gPD0gMjU1LAogICAgICAgICAnSU5WRU5UT1JZX1JPV19JREVOVElUWV9PUl9TVEFURV9JTlZBTElEJykKICAgIG5vdyA9IHRpbWVzdGFtcChvYnNlcnZlZF9hdF91dGMpCiAgICBjcmVhdGVkLCBzdGFydGVkLCBmaW5pc2hlZCA9ICh0aW1lc3RhbXAocm93W2tleV0pIGZvciBrZXkgaW4gKCdjcmVhdGVkX2F0JywgJ3N0YXJ0ZWRfYXQnLCAnZmluaXNoZWRfYXQnKSkKICAgIHplcm8gPSB0aW1lc3RhbXAoWkVSTykKICAgIG5lZWQoY3JlYXRlZCA+IHplcm8gYW5kIGNyZWF0ZWQgPD0gbm93ICsgNSwgJ0lOVkVOVE9SWV9DUkVBVEVEX1RJTUVfSU5WQUxJRCcpCiAgICBpZiByb3dbJ3J1bm5pbmcnXSBvciByb3dbJ3BpZCddID4gMCBvciByb3dbJ3N0YXR1cyddIGluICgncnVubmluZycsICdwYXVzZWQnLCAncmVzdGFydGluZycsICdzdG9wcGluZycpOgogICAgICAgIHJldHVybiAnTElWRScKICAgIGlmIChyb3dbJ3N0YXR1cyddID09ICdjcmVhdGVkJyBhbmQgcm93WydydW5uaW5nJ10gaXMgRmFsc2UgYW5kIHJvd1sncGlkJ10gPT0gMCBhbmQgcm93WydleGl0X2NvZGUnXSA9PSAwCiAgICAgICAgICAgIGFuZCBzdGFydGVkID09IHplcm8gYW5kIGZpbmlzaGVkID09IHplcm8pOgogICAgICAgIHJldHVybiAnQ1JFQVRFRF9ORVZFUl9TVEFSVEVEJwogICAgaWYgKHJvd1snc3RhdHVzJ10gaW4gKCdzdG9wcGVkJywgJ2V4aXRlZCcpIGFuZCByb3dbJ3J1bm5pbmcnXSBpcyBGYWxzZSBhbmQgcm93WydwaWQnXSA9PSAwCiAgICAgICAgICAgIGFuZCBzdGFydGVkICE9IHplcm8gYW5kIGZpbmlzaGVkICE9IHplcm8gYW5kIGNyZWF0ZWQgPD0gc3RhcnRlZCA8PSBmaW5pc2hlZCA8PSBub3cgKyA1KToKICAgICAgICByZXR1cm4gJ1NUT1BQRURfTk9OX0xJVkUnCiAgICByZXR1cm4gJ1VOS05PV04nCgoKZGVmIHZhbGlkYXRlX3NuYXBzaG90KHZhbHVlKToKICAgIG5lZWQodHlwZSh2YWx1ZSkgaXMgZGljdCBhbmQgc2V0KHZhbHVlKSA9PSBTTkFQU0hPVF9LRVlTLCAnSU5WRU5UT1JZX1NOQVBTSE9UX0ZJRUxEU19JTlZBTElEJykKICAgIHRpbWVzdGFtcCh2YWx1ZVsnb2JzZXJ2ZWRfYXRfdXRjJ10pCiAgICByb3dzID0gdmFsdWVbJ3Byb2R1Y2VycyddCiAgICBuZWVkKHR5cGUocm93cykgaXMgbGlzdCBhbmQgbGVuKHJvd3MpIDw9IE1BWF9SRUxFVkFOVAogICAgICAgICBhbmQgdHlwZSh2YWx1ZVsncm9vdGxlc3NfY29udGFpbmVyX2NvdW50J10pIGlzIGludAogICAgICAgICBhbmQgbGVuKHJvd3MpICsgMyA8PSB2YWx1ZVsncm9vdGxlc3NfY29udGFpbmVyX2NvdW50J10gPD0gTUFYX1JPT1RMRVNTCiAgICAgICAgIGFuZCBkaWdlc3QodmFsdWVbJ3Jvb3RsZXNzX2ludmVudG9yeV9zaGEyNTYnXSksICdJTlZFTlRPUllfU05BUFNIT1RfQk9VTkRTX0lOVkFMSUQnKQogICAgaWRzLCBuYW1lcyA9IFtdLCBzZXQoKQogICAgY291bnRzID0geydsaXZlX3Byb2R1Y2VyX2NvdW50JzogMCwgJ3Vua25vd25fcHJvZHVjZXJfY291bnQnOiAwLCAnbmV2ZXJfc3RhcnRlZF9wcm9kdWNlcl9jb3VudCc6IDAsCiAgICAgICAgICAgICAgJ3N0b3BwZWRfbm9uX2xpdmVfcHJvZHVjZXJfY291bnQnOiAwfQogICAga2V5cyA9IHsnTElWRSc6ICdsaXZlX3Byb2R1Y2VyX2NvdW50JywgJ1VOS05PV04nOiAndW5rbm93bl9wcm9kdWNlcl9jb3VudCcsCiAgICAgICAgICAgICdDUkVBVEVEX05FVkVSX1NUQVJURUQnOiAnbmV2ZXJfc3RhcnRlZF9wcm9kdWNlcl9jb3VudCcsICdTVE9QUEVEX05PTl9MSVZFJzogJ3N0b3BwZWRfbm9uX2xpdmVfcHJvZHVjZXJfY291bnQnfQogICAgZm9yIHJvdyBpbiByb3dzOgogICAgICAgIG5lZWQodHlwZShyb3cpIGlzIGRpY3QgYW5kIHNldChyb3cpID09IFJPV19LRVlTIHwgeydjbGFzc2lmaWNhdGlvbid9LCAnSU5WRU5UT1JZX1JPV19GSUVMRFNfSU5WQUxJRCcpCiAgICAgICAgcmF3ID0ge2tleTogcm93W2tleV0gZm9yIGtleSBpbiBST1dfS0VZU30KICAgICAgICBraW5kID0gY2xhc3NpZnlfcm93KHJhdywgdmFsdWVbJ29ic2VydmVkX2F0X3V0YyddKQogICAgICAgIG5lZWQocm93WydjbGFzc2lmaWNhdGlvbiddID09IGtpbmQgYW5kIHJvd1snY2xhc3NpZmljYXRpb24nXSBpbiBDTEFTU0lGSUNBVElPTlMsCiAgICAgICAgICAgICAnSU5WRU5UT1JZX0NMQVNTSUZJQ0FUSU9OX01JU01BVENIJykKICAgICAgICBuZWVkKHJvd1snaWQnXSBub3QgaW4gaWRzIGFuZCByb3dbJ25hbWUnXSBub3QgaW4gbmFtZXMsICdJTlZFTlRPUllfRFVQTElDQVRFX1JPVycpCiAgICAgICAgaWRzLmFwcGVuZChyb3dbJ2lkJ10pOyBuYW1lcy5hZGQocm93WyduYW1lJ10pOyBjb3VudHNba2V5c1traW5kXV0gKz0gMQogICAgbmVlZChpZHMgPT0gc29ydGVkKGlkcyksICdJTlZFTlRPUllfUk9XU19OT1RfQ0FOT05JQ0FMJykKICAgIHJldHVybiBjb3VudHMKCgpkZWYgc3RhYmxlX3NuYXBzaG90KHZhbHVlKToKICAgICIiIldpdGhpbiBvbmUgb2JzZXJ2YXRpb24sIG9ubHkgc2FtcGxpbmcgdGltZSBtYXkgZGlmZmVyLiIiIgogICAgdmFsaWRhdGVfc25hcHNob3QodmFsdWUpCiAgICByZXR1cm4ge2tleTogdmFsdWVba2V5XSBmb3Iga2V5IGluIFNOQVBTSE9UX0tFWVMgaWYga2V5ICE9ICdvYnNlcnZlZF9hdF91dGMnfQoKCmRlZiB2YWxpZGF0ZV93aXRuZXNzKHZhbHVlLCBvYnNlcnZlZF9hdF91dGMpOgogICAgbmVlZCh0eXBlKHZhbHVlKSBpcyBkaWN0IGFuZCBzZXQodmFsdWUpID09IHsnc2NoZW1hX3ZlcnNpb24nLCAnc2NvcGUnLCAnYmVmb3JlJywgJ2FmdGVyJ30KICAgICAgICAgYW5kIHR5cGUodmFsdWVbJ3NjaGVtYV92ZXJzaW9uJ10pIGlzIGludCBhbmQgdmFsdWVbJ3NjaGVtYV92ZXJzaW9uJ10gPT0gMSBhbmQgdmFsdWVbJ3Njb3BlJ10gPT0gU0NPUEUsCiAgICAgICAgICdJTlZFTlRPUllfV0lUTkVTU19GSUVMRFNfSU5WQUxJRCcpCiAgICByYXcgPSBjYW5vbmljYWwodmFsdWUpCiAgICBuZWVkKDAgPCBsZW4ocmF3KSA8PSBNQVhfV0lUTkVTU19CWVRFUywgJ0lOVkVOVE9SWV9XSVRORVNTX1RPT19MQVJHRScpCiAgICBiZWZvcmVfY291bnRzID0gdmFsaWRhdGVfc25hcHNob3QodmFsdWVbJ2JlZm9yZSddKQogICAgYWZ0ZXJfY291bnRzID0gdmFsaWRhdGVfc25hcHNob3QodmFsdWVbJ2FmdGVyJ10pCiAgICBiZWZvcmUgPSB0aW1lc3RhbXAodmFsdWVbJ2JlZm9yZSddWydvYnNlcnZlZF9hdF91dGMnXSkKICAgIGFmdGVyID0gdGltZXN0YW1wKHZhbHVlWydhZnRlciddWydvYnNlcnZlZF9hdF91dGMnXSkKICAgIG9ic2VydmVkID0gdGltZXN0YW1wKG9ic2VydmVkX2F0X3V0YykKICAgIG5lZWQoYmVmb3JlIDw9IGFmdGVyIDw9IG9ic2VydmVkICsgNSBhbmQgYWZ0ZXIgLSBiZWZvcmUgPD0gMTIwIGFuZCBvYnNlcnZlZCAtIGJlZm9yZSA8PSAxNTAsCiAgICAgICAgICdJTlZFTlRPUllfV0lUTkVTU19USU1FX0lOVkFMSUQnKQogICAgbmVlZChzdGFibGVfc25hcHNob3QodmFsdWVbJ2JlZm9yZSddKSA9PSBzdGFibGVfc25hcHNob3QodmFsdWVbJ2FmdGVyJ10pIGFuZCBiZWZvcmVfY291bnRzID09IGFmdGVyX2NvdW50cywKICAgICAgICAgJ0lOVkVOVE9SWV9DSEFOR0VEX1dJVEhJTl9PQlNFUlZBVElPTicpCiAgICBuZWVkKGFmdGVyX2NvdW50c1snbGl2ZV9wcm9kdWNlcl9jb3VudCddID09IGFmdGVyX2NvdW50c1sndW5rbm93bl9wcm9kdWNlcl9jb3VudCddID09IDAsCiAgICAgICAgICdJTlZFTlRPUllfTElWRV9PUl9VTktOT1dOX1BST0RVQ0VSX1BSRVNFTlQnKQogICAgcmV0dXJuIGRpY3QoYWZ0ZXJfY291bnRzLCBpbnZlbnRvcnlfZXZpZGVuY2Vfc2hhMjU2PWhhc2hsaWIuc2hhMjU2KHJhdykuaGV4ZGlnZXN0KCkpCg=='
_SYNCHRONOUS_FILES = {'stage_receipt_sha256': 'stage-receipt.json',
    'launch_receipt_sha256': 'launch-receipt.json', 'launch_intent_sha256': 'launch-intent.json',
    'dispatch_receipt_sha256': 'dispatch-receipt.json', 'qa_report_sha256': 'qa-result.json'}
_SYNCHRONOUS_LINKS = set(_SYNCHRONOUS_FILES) | {
    'qa_run_intent_sha256', 'qa_run_completion_sha256', 'qa_source_sha256',
    'wrapper_sha256', 'original_wrapper_sha256'}
_SYNCHRONOUS_KEYS = (_PRODUCER_KEYS - {'container_id'}) | _SYNCHRONOUS_LINKS | {
    'termination_basis', 'container_forensic_attribution', 'detached', 'timed_out',
    'signal_number', 'producer_inventory_complete', 'unknown_producer_count'}
_SYNCHRONOUS_INVENTORY_KEYS = _SYNCHRONOUS_KEYS | {
    'inventory_evidence', 'inventory_evidence_sha256', 'never_started_producer_count',
    'stopped_non_live_producer_count', 'classification_contract_sha256'}
OBSERVATION_PURPOSES = frozenset({'failure_disposition', 'retry_reservation'})
_OBSERVATION_TABLE = 'verification_producer_observations'
_DISPOSITION_KEYS = {'schema_version', 'scope', 'failure_class', 'binding', 'claim_sha256',
    'session_id', 'qa_run_id', 'plan_sha256', 'collection_manifest_sha256', 'qa_report_sha256',
    'allocation_receipt_sha256', 'verification_profile_sha256', 'journal_summary_sha256',
    'evidence_sha256', 'producer', 'human_acceptance_recorded', 'automatic_retry_permitted'}


class RecoveryError(RuntimeError):
    """Bounded categories only; source, tokens and diagnostic text are withheld."""


def _need(ok, code):
    if not ok:
        raise RecoveryError(code)


def digest(raw):
    _need(type(raw) is bytes, 'RECOVERY_EXACT_BYTES_REQUIRED')
    return hashlib.sha256(raw).hexdigest()


def classification_contract():
    """Compile only the exact reviewed pure classifier; no caller code or I/O.

    C bootstrap cannot install new runtime sources. Its separately source-pinned
    backend carries the identical shared bytes. Fresh compilation also prevents
    a mutable cached module/caller callback from replacing validation functions.
    The new runtime still ships and attests the same standalone source file.
    """
    try:
        raw = base64.b64decode(_CLASSIFICATION_SOURCE_B64, validate=True)
        _need(digest(raw) == CLASSIFICATION_CONTRACT_SHA256, 'RECOVERY_INVENTORY_CONTRACT_CHANGED')
        module = types.ModuleType('_fox_reviewed_inventory_contract')
        exec(compile(raw, '<reviewed-inventory-contract>', 'exec'), module.__dict__)
        return module
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError('RECOVERY_INVENTORY_CONTRACT_UNAVAILABLE') from None


# Compatibility for pure fixture generation; authoritative validation below
# always compiles a fresh exact-byte module and does not trust this cached copy.
_inventory_contract = classification_contract()


def canonical_bytes(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise RecoveryError('RECOVERY_JSON_INVALID') from None


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _load(raw, maximum=2_000_000):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, 'RECOVERY_INPUT_BOUNDS')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, 'RECOVERY_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise RecoveryError('RECOVERY_JSON_INVALID') from None
    _need(type(value) is dict, 'RECOVERY_JSON_OBJECT_REQUIRED')
    return value


def _time(value):
    _need(type(value) is str and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)', value),
        'RECOVERY_UTC_REQUIRED')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError:
        raise RecoveryError('RECOVERY_UTC_INVALID') from None


def _clock(now):
    value = now or datetime.now(timezone.utc)
    _need(isinstance(value, datetime) and value.tzinfo is not None, 'RECOVERY_CLOCK_REQUIRED')
    return value


def claim_sha256(claim):
    _need(type(claim) is Claim, 'RECOVERY_ORIGINAL_CLAIM_REQUIRED')
    return digest(canonical_bytes({'binding': claim.binding.payload(), 'attempt_token': claim.attempt_token}))


def producer_identity(producer):
    """Stable identity of an already fully validated producer observation.

    This comparison helper grants no authority and does not replace witness,
    freshness, runtime-attestation, or held-lease validation. The original
    observation is immutable; separately validated later v2 inventories may move.
    """
    _need(type(producer) is dict, 'RECOVERY_PRODUCER_FIELDS')
    scope = producer.get('scope')
    variants = {
        'fox-verification-producer-observation-v1': (1, _PRODUCER_KEYS),
        SYNCHRONOUS_SCOPE: (1, _SYNCHRONOUS_KEYS),
        SYNCHRONOUS_INVENTORY_SCOPE: (2, _SYNCHRONOUS_INVENTORY_KEYS),
    }
    _need(type(scope) is str and scope in variants, 'RECOVERY_PRODUCER_SCOPE_UNSUPPORTED')
    version, fields = variants[scope]
    _need(set(producer) == fields and type(producer['schema_version']) is int
          and producer['schema_version'] == version, 'RECOVERY_PRODUCER_FIELDS')
    changing = {'observed_at_utc'}
    if scope == SYNCHRONOUS_INVENTORY_SCOPE:
        changing |= {'inventory_evidence', 'inventory_evidence_sha256', 'never_started_producer_count',
                     'stopped_non_live_producer_count'}
    return deepcopy_json({key: value for key, value in producer.items() if key not in changing})


@dataclass(frozen=True)
class ReviewedSynchronousLaunch:
    """Protected configuration, never reconstructed from an operator request.

    A reviewer must approve the exact original/generated wrapper pair and the
    full launcher/source release: synchronous foreground execution, bounded
    timeout, --rm, and no detached/background path. Hash shape is not that review.
    The generated wrapper may differ only by the reviewed pinned-image change.
    No arbitrary shell text is interpreted or accepted as proof of these facts.
    """
    verifier_release_sha256: str
    qa_source_sha256: str
    wrapper_sha256: str
    original_wrapper_sha256: str
    image_id: str

    def __post_init__(self):
        _need(all(_sha(value) for value in (self.verifier_release_sha256, self.qa_source_sha256,
                   self.wrapper_sha256, self.original_wrapper_sha256)), 'RECOVERY_REVIEWED_LAUNCH_INVALID')
        _need(type(self.image_id) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', self.image_id),
              'RECOVERY_REVIEWED_IMAGE_INVALID')


def _synchronous_producer(value, binding, session_id, qa_run_id, image_id, now, *,
                          reviewed, links, finished=None):
    """A separate terminal-launch proof, not container-level forensic evidence."""
    _need(type(reviewed) is ReviewedSynchronousLaunch, 'RECOVERY_REVIEWED_SYNCHRONOUS_LAUNCH_REQUIRED')
    _need(type(value) is dict and set(value) == _SYNCHRONOUS_KEYS, 'RECOVERY_SYNCHRONOUS_PRODUCER_FIELDS')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and value['scope'] == SYNCHRONOUS_SCOPE
          and value['binding_sha256'] == digest(canonical_bytes(binding.payload()))
          and value['session_id'] == session_id and value['qa_run_id'] == qa_run_id
          and value['image_id'] == image_id and value['state'] == 'STOPPED'
          and type(value['exit_code']) is int and value['exit_code'] == 2
          and value['termination_basis'] == 'synchronous_foreground_exit'
          and value['container_forensic_attribution'] is False and value['detached'] is False
          and value['timed_out'] is False and value['signal_number'] is None
          and value['producer_inventory_complete'] is True, 'RECOVERY_SYNCHRONOUS_TERMINALITY_UNPROVEN')
    _need(all(type(value[key]) is int and value[key] == 0 for key in
              ('live_producer_count', 'unknown_producer_count', 'unresolved_phase_count',
               'technical_proof_count', 'human_acceptance_count')), 'RECOVERY_PRODUCER_OR_OUTCOME_UNRESOLVED')
    _need(binding.verifier_release_sha256 == reviewed.verifier_release_sha256
          and image_id == reviewed.image_id
          and value['qa_source_sha256'] == reviewed.qa_source_sha256
          and value['wrapper_sha256'] == reviewed.wrapper_sha256
          and value['original_wrapper_sha256'] == reviewed.original_wrapper_sha256
          and type(links) is dict and set(links) == _SYNCHRONOUS_LINKS
          and all(_sha(links[key]) and value[key] == links[key] for key in _SYNCHRONOUS_LINKS),
          'RECOVERY_SYNCHRONOUS_EVIDENCE_CHANGED')
    observed = _time(value['observed_at_utc'])
    _need(-5 <= _clock(now).timestamp() - observed <= 300
          and (finished is None or finished <= observed + 5), 'RECOVERY_PRODUCER_OBSERVATION_STALE')


def _synchronous_inventory_producer(value, binding, session_id, qa_run_id, image_id, now, *,
                                    reviewed, links, finished=None):
    """Independently classify exact, complete before/after inventory evidence."""
    _need(type(value) is dict and set(value) == _SYNCHRONOUS_INVENTORY_KEYS
          and type(value['schema_version']) is int and value['schema_version'] == 2
          and value['scope'] == SYNCHRONOUS_INVENTORY_SCOPE,
          'RECOVERY_INVENTORY_PRODUCER_FIELDS')
    inventory_contract = classification_contract()
    try:
        _need(value['classification_contract_sha256'] == CLASSIFICATION_CONTRACT_SHA256,
              'RECOVERY_INVENTORY_CONTRACT_CHANGED')
        counts = inventory_contract.validate_witness(value['inventory_evidence'], value['observed_at_utc'])
    except inventory_contract.InventoryContractError:
        raise RecoveryError('RECOVERY_INVENTORY_WITNESS_INVALID') from None
    _need(all(type(value[key]) is int and value[key] == counts[key] for key in
              ('live_producer_count', 'unknown_producer_count', 'never_started_producer_count',
               'stopped_non_live_producer_count'))
          and value['inventory_evidence_sha256'] == counts['inventory_evidence_sha256'],
          'RECOVERY_INVENTORY_COUNTS_OR_DIGEST_CHANGED')
    # Reuse the immutable synchronous-launch proof without weakening its v1
    # exact-field contract. This projection is not the retained observation.
    legacy = {key: value[key] for key in _SYNCHRONOUS_KEYS}
    legacy.update(schema_version=1, scope=SYNCHRONOUS_SCOPE)
    _synchronous_producer(legacy, binding, session_id, qa_run_id, image_id, now,
                         reviewed=reviewed, links=links, finished=finished)


def _synchronous_links(*, files, stage, collection, summary, reviewed, wrapper_raw):
    _need(type(reviewed) is ReviewedSynchronousLaunch, 'RECOVERY_REVIEWED_SYNCHRONOUS_LAUNCH_REQUIRED')
    _need(type(wrapper_raw) is bytes and 0 < len(wrapper_raw) <= 65_536
          and digest(wrapper_raw) == reviewed.wrapper_sha256, 'RECOVERY_REVIEWED_WRAPPER_CHANGED')
    # These are raw collection members, not reserialized equivalents. Neither
    # wrapper is added to or used to rewrite the retained collection manifest.
    expected = {'source/run-native-v2.sh': reviewed.wrapper_sha256,
        'source/run-jsn-qa.sh': reviewed.original_wrapper_sha256,
        **{stage_name: digest(files[name]) for stage_name, name in {
            'inputs/package.zip': 'package.zip', 'inputs/native-form-spec.json': 'native-form-spec.json',
            'inputs/allocate.evidence.json': 'allocation-receipt.json',
            'inputs/verification-profile.json': 'verification-profile.json',
            'inputs/verify.evidence.json': 'clean-import-receipt.json',
            'prepared/target.json': 'target-receipt.json', 'prepared/profile.json': 'qa-profile.json'}.items()}}
    bound = stage.get('bound_files')
    _need(type(bound) is dict and all(bound.get(name) == value for name, value in expected.items())
          and collection['source_sha256'] == reviewed.qa_source_sha256,
          'RECOVERY_SYNCHRONOUS_STAGE_BINDING_CHANGED')
    return {**{key: digest(files[name]) for key, name in _SYNCHRONOUS_FILES.items()},
        'qa_source_sha256': reviewed.qa_source_sha256, 'wrapper_sha256': reviewed.wrapper_sha256,
        'original_wrapper_sha256': reviewed.original_wrapper_sha256,
        'qa_run_intent_sha256': summary['phases']['qa_run']['intent_sha256'],
        'qa_run_completion_sha256': summary['phases']['qa_run']['completion_sha256']}


def _producer(value, binding, session_id, qa_run_id, image_id, now, finished=None):
    _need(type(value) is dict and set(value) == _PRODUCER_KEYS, 'RECOVERY_PRODUCER_FIELDS')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and value['scope'] == 'fox-verification-producer-observation-v1'
          and value['binding_sha256'] == digest(canonical_bytes(binding.payload()))
          and value['session_id'] == session_id and value['qa_run_id'] == qa_run_id
          and _sha(value['container_id']) and value['image_id'] == image_id
          and value['state'] == 'STOPPED' and type(value['exit_code']) is int and value['exit_code'] == 2,
          'RECOVERY_PRODUCER_NOT_CONFIRMED_STOPPED')
    _need(all(type(value[key]) is int and value[key] == 0 for key in
              ('live_producer_count', 'unresolved_phase_count', 'technical_proof_count', 'human_acceptance_count')),
          'RECOVERY_PRODUCER_OR_OUTCOME_UNRESOLVED')
    observed = _time(value['observed_at_utc'])
    _need(-5 <= _clock(now).timestamp() - observed <= 300
          and (finished is None or finished <= observed + 5), 'RECOVERY_PRODUCER_OBSERVATION_STALE')


def _failed_cases(qa, plan):
    """Validate actual FAILED outcomes; never rewrite a report as PASSED."""
    _need(qa.get('status') == 'FAILED' and qa.get('dispatch_state') == 'ATTEMPT_INCOMPLETE'
          and type(qa.get('schema_version')) is int and qa['schema_version'] == 2
          and qa.get('test_scope') == 'authenticated_browser_native_table_form_synthetic_only',
          'RECOVERY_TERMINAL_FAILED_REPORT_REQUIRED')
    _need(canonical_bytes(qa.get('test_plan')) == canonical_bytes(plan)
          and qa.get('test_plan_sha256') == qa_plan_sha256(plan), 'RECOVERY_PLAN_DIFFERS')
    tests = qa.get('tests')
    _need(type(tests) is list and len(tests) == 14 and all(type(test) is dict for test in tests),
          'RECOVERY_CASE_SET_INVALID')
    names = [test.get('name') for test in tests]
    _need(all(type(name) is str for name in names) and len(set(names)) == 14
          and set(names) == {case['name'] for case in plan['cases']}, 'RECOVERY_CASE_SET_INVALID')
    indexed, failures = dict(zip(names, tests)), 0
    for case in plan['cases']:
        test = indexed[case['name']]
        _need(test.get('applicable') is case['applicable'] and test.get('required') is case['applicable']
              and test.get('reason_code') == case['reason_code']
              and test.get('field_names') == case['field_names'], 'RECOVERY_APPLICABILITY_CHANGED')
        if not case['applicable']:
            _need(test.get('status') == 'NOT_APPLICABLE' and test.get('field_results') == [],
                  'RECOVERY_INAPPLICABLE_CASE_CHANGED')
            continue
        _need(test.get('status') in ('PASSED', 'FAILED', 'NOT_RUN'), 'RECOVERY_CASE_OUTCOME_UNKNOWN')
        expected = [{'field_name': name, 'status': 'PASSED'} for name in case['field_names']]
        results = test.get('field_results')
        _need(type(results) is list and canonical_bytes(results) == canonical_bytes(expected[:len(results)]),
              'RECOVERY_FIELD_RESULTS_CHANGED')
        if test['status'] == 'PASSED':
            _need(results == expected, 'RECOVERY_PASSED_FIELD_COVERAGE_MISSING')
        else:
            browser_errors = qa.get('browser_errors')
            error_count = test.get('evidence', {}).get('unhandled_error_count')
            explicit_browser_failure = (case['name'] == 'browser_runtime_errors' and test['status'] == 'FAILED'
                and type(browser_errors) is list and type(error_count) is int
                and 0 < error_count == len(browser_errors))
            _need(explicit_browser_failure or
                  (type(test.get('reason')) is str and 0 < len(test['reason'].strip()) <= 2000),
                  'RECOVERY_FAILED_OR_UNRUN_REASON_REQUIRED')
            if test['status'] == 'NOT_RUN':
                _need(results == [], 'RECOVERY_UNRUN_FIELD_RESULTS_INVALID')
            failures += test['status'] == 'FAILED'
    _need(failures > 0, 'RECOVERY_APPLICABLE_FAILURE_REQUIRED')


def _retained_plan(plan, raw, *, binding, package, native, native_raw, release, member_hashes, policy, allocation):
    """Check the immutable clean-plan contract against independently checked bytes.

    Versions come from the retained policy, not today's active version allowlist.
    This is an integrity check only; it does not authorize a new clean install.
    """
    _need(set(plan) == {'schema_version', 'scope', 'policy_id', 'created_at_utc', 'operator_code_sha256',
                       'source_origin', 'binding', 'target', 'expected_versions'}
          and raw == canonical_bytes(plan) and type(plan['schema_version']) is int
          and plan['schema_version'] == 1 and plan['scope'] == 'fox-clean-install-plan-v2'
          and plan['policy_id'] == POLICY_ID and _sha(plan['operator_code_sha256']),
          'RECOVERY_CLEAN_PLAN_CONTRACT_CHANGED')
    created = _time(plan['created_at_utc'])
    target = {key: value for key, value in allocation['target'].items()
              if key not in {'workspace_id', 'application_id'}}
    _need(plan['target'] == target and plan['expected_versions'] == policy.versions
          and datetime.fromtimestamp(created, timezone.utc).strftime('%y%m%d') == target['workspace'][7:13]
          and created <= _time(allocation['allocated_at_utc']), 'RECOVERY_CLEAN_PLAN_TARGET_CHANGED')
    origin = plan['source_origin']
    _need(type(origin) is dict and set(origin) == {'schema_version', 'scope', 'observed_at_utc',
          'instance_id', 'compartment_id', 'region', 'job_id', 'run_state', 'package_sha256',
          'package_bytes', 'source_manifest_sha256'}, 'RECOVERY_CLEAN_PLAN_ORIGIN_CHANGED')
    _need(type(origin['schema_version']) is int and origin['schema_version'] == 1
          and origin['scope'] == 'fox-private-job-package-read-v1'
          and origin['instance_id'] == INSTANCE
          and all(origin[key] == policy.target[key] for key in ('compartment_id', 'region'))
          and origin['run_state'] in {'QA_REQUIRED', 'VERIFIED', 'ACCEPTED'}
          and type(origin['package_bytes']) is int and origin['package_bytes'] == len(package)
          and -5 <= created - _time(origin['observed_at_utc']) <= 86_400,
          'RECOVERY_CLEAN_PLAN_ORIGIN_CHANGED')
    identity = {key: value for key, value in binding.payload().items() if key != 'verifier_release_sha256'}
    _need(all(origin[key] == value for key, value in identity.items()), 'RECOVERY_CLEAN_PLAN_ORIGIN_CHANGED')
    app, reimport = release['application_id'], release['package_reimport']['application_id']
    alias = 'F2A_' + binding.job_id.upper().replace('-', '_')
    _need(all(type(value) is int and 0 < value <= 9_007_199_254_740_991 for value in (app, reimport))
          and app != reimport and release['application_alias'] == alias
          and release['package_reimport']['application_alias'] == alias + '_SQLCHECK'
          and allocation['target']['application_id'] not in {app, reimport, 103},
          'RECOVERY_CLEAN_PLAN_SOURCE_IDENTITIES_CHANGED')
    expected = {**identity, 'source_application_id': app, 'source_application_alias': alias,
        'source_reimport_application_id': reimport, 'source_reimport_application_alias': alias + '_SQLCHECK',
        'sql_member': 'sql/f' + str(app) + '.sql', 'schema_member': 'schema/01_synthetic_schema.sql',
        'sql_sha256': member_hashes['sql/f' + str(app) + '.sql'],
        'schema_script_sha256': member_hashes['schema/01_synthetic_schema.sql'],
        'native_spec_sha256': digest(native_raw), 'table_name': native['table_name'], 'profile_id': native['profile_id']}
    _need(type(plan['binding']) is dict and canonical_bytes(plan['binding']) == canonical_bytes(expected),
          'RECOVERY_CLEAN_PLAN_PACKAGE_CHANGED')


def validate_failed_evidence(*, binding, package, plan_raw, collection_raw, files,
                             journal_summary, producer, now, reviewed_synchronous_launch=None, wrapper_raw=None):
    """Pure operator-evidence validation. A returned document grants no authority.

    Journal summaries must be derived from all original private session files by
    the protected resolver. Hashes are integrity links, not vendor signatures.
    A server write additionally requires its own fresh authoritative probe.
    """
    try:
        _need(type(binding) is VerificationBinding, 'RECOVERY_BINDING_REQUIRED')
        _need(type(files) is dict and set(files) == FILES and all(type(raw) is bytes for raw in files.values()),
              'RECOVERY_EVIDENCE_SET_INVALID')
        _need(type(package) is bytes and 0 < len(package) <= 8_000_000
              and files['package.zip'] == package and digest(package) == binding.package_sha256,
              'RECOVERY_PACKAGE_CHANGED')
        _need(all(0 < len(raw) <= (8_000_000 if name == 'package.zip' else 2_000_000)
                  for name, raw in files.items()), 'RECOVERY_INPUT_BOUNDS')
        plan, collection = _load(plan_raw, 65_536), _load(collection_raw, 65_536)
        _need(collection.get('status') == 'COLLECTED' and collection.get('credentials_and_logs_excluded') is True
              and collection.get('plan_sha256') == digest(plan_raw)
              and _sha(collection.get('source_sha256'))
              and type(collection.get('sha256')) is dict and set(collection['sha256']) == FILES
              and all(collection['sha256'][name] == digest(raw) for name, raw in files.items()),
              'RECOVERY_COLLECTION_CHANGED')
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            native_raw = archive.read('native-form-spec.json')
            native = _load(native_raw)
            release = _load(archive.read('evidence/release-evidence.json'))
            member_hashes = {name: digest(archive.read(name)) for name in
                ('sql/f' + str(release['application_id']) + '.sql', 'schema/01_synthetic_schema.sql')}
        _need(native_raw == files['native-form-spec.json']
              and verify_package(package, release, native) == binding.package_sha256,
              'RECOVERY_PACKAGE_INVALID')
        policy = BoundVerificationPolicy(files['verification-profile.json'], historical=True)
        allocation = validate_allocation_receipt(files['allocation-receipt.json'], policy)
        _retained_plan(plan, plan_raw, binding=binding, package=package, native=native, native_raw=native_raw,
                       release=release, member_hashes=member_hashes, policy=policy, allocation=allocation)
        identity = {key: value for key, value in binding.payload().items() if key != 'verifier_release_sha256'}
        _need(all(policy.binding[key] == value and release.get(key) == value
                  for key, value in identity.items() if key != 'package_sha256')
              and policy.binding['package_sha256'] == binding.package_sha256
              and allocation['plan_sha256'] == digest(plan_raw)
              and all(plan.get('binding', {}).get(key) == value for key, value in identity.items()),
              'RECOVERY_JOB_SOURCE_PLAN_CHANGED')
        clean, target, profile, qa, stage, launch, intent, dispatch = [
            _load(files[name]) for name in ('clean-import-receipt.json', 'target-receipt.json', 'qa-profile.json',
                'qa-result.json', 'stage-receipt.json', 'launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json')]
        hashes = {'allocation_receipt_sha256': digest(files['allocation-receipt.json']),
                  'verification_profile_sha256': policy.sha256, 'native_spec_sha256': digest(native_raw),
                  **identity}
        _need(clean.get('scope') == 'fox-clean-package-install-v2' and clean.get('passed') is True
              and clean.get('schema_version') == 2 and target.get('schema_version') == 2
              and all(clean.get(key) == value and target.get(key) == value for key, value in hashes.items())
              and all(clean.get(key) == value for key, value in policy.target.items())
              and all(target.get(key) == value for key, value in policy.target.items() if key != 'application_alias')
              and target.get('alias') == policy.target['application_alias']
              and target.get('clean_install') is True and target.get('synthetic_qa_approved') is True,
              'RECOVERY_CLEAN_TARGET_CHANGED')
        install = clean.get('clean_install', {})
        before, after = install.get('before_install', {}), install.get('after_install', {})
        _need(all(install.get(key) is True for key in ('passed', 'workspace_created_fresh', 'schema_created_fresh'))
              and before.get('passed') is True and after.get('passed') is True
              and all(type(before.get(key)) is int and before[key] == 0 for key in ('application_count', 'user_object_count'))
              and all(type(after.get(key)) is int and after[key] == value for key, value in {
                  'application_count': 1, 'native_table_count': 1, 'unexpected_schema_dependency_count': 0, 'initial_row_count': 0}.items())
              and all(clean.get('observed_versions', {}).get(key) == value for key, value in policy.versions.items()),
              'RECOVERY_CLEAN_PHASE_UNPROVEN')
        _need(target.get('profile_sha256') == digest(files['qa-profile.json'])
              and target.get('import_receipt_sha256') == digest(files['clean-import-receipt.json'])
              and canonical_bytes(profile) == canonical_bytes(derive_native_qa_profile(native))
              and qa.get('target') == target and qa.get('target_receipt_sha256') == digest(files['target-receipt.json']),
              'RECOVERY_QA_TARGET_CHANGED')
        qa_binding = qa.get('binding', {})
        _need(qa_binding.get('scope') == 'exact-package-clean-install-v2'
              and qa_binding.get('package_sha256') == binding.package_sha256
              and qa_binding.get('verification_profile_sha256') == policy.sha256
              and all(qa_binding.get(key) is True for key in ('profile_bytes_verified', 'package_bytes_verified',
                'native_spec_bytes_verified', 'import_receipt_bytes_verified', 'package_manifest_verified',
                'clean_install_verified', 'verification_profile_bytes_verified'))
              and all(qa.get(key) is False for key in ('human_acceptance_recorded', 'credentials_recorded', 'browser_storage_saved')),
              'RECOVERY_QA_BYTE_BINDING_INCOMPLETE')
        derived = derive_native_qa_plan(native, digest(native_raw))
        _failed_cases(qa, derived)
        qa_id = qa.get('run_id')
        _need(type(qa_id) is str and _QA_RUN.fullmatch(qa_id), 'RECOVERY_QA_RUN_INVALID')
        started, finished = _time(qa.get('started_at')), _time(qa.get('finished_at'))
        _need(_time(allocation['allocated_at_utc']) <= _time(clean['started_at_utc'])
              <= _time(clean['finished_at_utc']) <= started <= finished, 'RECOVERY_EVIDENCE_SEQUENCE_INVALID')
        image = qa.get('runtime', {}).get('image_id')
        _need(type(image) is str and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', image), 'RECOVERY_QA_IMAGE_INVALID')
        image = 'sha256:' + image.removeprefix('sha256:')
        for value in (stage, launch, intent):
            _need(value.get('plan_sha256') == digest(plan_raw)
                  and value.get('source_sha256') == collection.get('source_sha256')
                  and 'sha256:' + str(value.get('image_id')).removeprefix('sha256:') == image,
                  'RECOVERY_LAUNCH_BINDING_CHANGED')
        _need(stage.get('status') == 'STAGED'
              and stage.get('allocation_receipt_sha256') == hashes['allocation_receipt_sha256']
              and launch.get('status') == 'QA_FAILED_OR_INCOMPLETE'
              and type(launch.get('exit_code')) is int and launch['exit_code'] == 2
              and launch.get('automatic_replay_permitted') is False
              and intent.get('scope') == 'fox-native-qa-launch-v2'
              and intent.get('state') == 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'
              and intent.get('allocation_receipt_sha256') == hashes['allocation_receipt_sha256'],
              'RECOVERY_TERMINAL_LAUNCH_REQUIRED')
        _need(dispatch.get('scope') == 'fox-native-qa-dispatch-v2'
              and dispatch.get('state') == 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY'
              and dispatch.get('run_id') == qa_id and dispatch.get('job_id') == binding.job_id
              and all(dispatch.get(key) == value for key, value in {
                  'package_sha256': binding.package_sha256, 'allocation_receipt_sha256': hashes['allocation_receipt_sha256'],
                  'verification_profile_sha256': policy.sha256, 'target_receipt_sha256': digest(files['target-receipt.json']),
                  'profile_sha256': digest(files['qa-profile.json']), 'test_plan_sha256': qa_plan_sha256(derived)}.items()),
              'RECOVERY_DISPATCH_CHANGED')
        _need('sha256:' + str(dispatch.get('image_id')).removeprefix('sha256:') == image,
              'RECOVERY_DISPATCH_IMAGE_CHANGED')
        summary = journal_summary
        _need(type(summary) is dict and set(summary) == {'schema_version', 'scope', 'session_id', 'release_sha256',
              'binding_sha256', 'claim_sha256', 'retained_sha256', 'phases', 'unresolved_intents',
              'promotion_attempted', 'queue_completion_attempted'}, 'RECOVERY_JOURNAL_FIELDS')
        _need(type(summary['schema_version']) is int and summary['schema_version'] == 1
              and summary['scope'] == 'fox-verification-failed-journal-summary-v1'
              and type(summary['session_id']) is str and _SESSION.fullmatch(summary['session_id'])
              and summary['release_sha256'] == binding.verifier_release_sha256
              and summary['binding_sha256'] == digest(canonical_bytes(binding.payload())) and _sha(summary['claim_sha256'])
              and summary['unresolved_intents'] == [] and summary['promotion_attempted'] is False
              and summary['queue_completion_attempted'] is False, 'RECOVERY_JOURNAL_UNRESOLVED')
        retained = summary['retained_sha256']
        _need(type(retained) is dict and {'session.json', 'attention.json'} <= set(retained)
              and all(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,95}', name) and _sha(value)
                      for name, value in retained.items())
              and type(summary['phases']) is dict and set(summary['phases']) == set(PHASES), 'RECOVERY_PHASE_COVERAGE')
        for name in retained:
            if name in {'session.json', 'attention.json'}:
                continue
            match = re.fullmatch(r'(p[0-9]{4})-([a-z-]+)\.(intent|complete)\.json', name)
            _need(match is not None and match[2] in {'claim'} | {phase.replace('_', '-') for phase in PHASES},
                  'RECOVERY_UNKNOWN_OR_PROMOTION_PHASE')
            counterpart = match[1] + '-' + match[2] + ('.complete.json' if match[3] == 'intent' else '.intent.json')
            _need(counterpart in retained, 'RECOVERY_UNRESOLVED_RETAINED_INTENT')
        phase_prefix = None
        for phase, evidence in summary['phases'].items():
            _need(type(evidence) is dict and set(evidence) == {'intent_sha256', 'completion_sha256', 'result'}
                  and all(_sha(evidence[key]) and evidence[key] in retained.values()
                          for key in ('intent_sha256', 'completion_sha256')), 'RECOVERY_PHASE_HASH_CHANGED')
            candidates = []
            for name, value in retained.items():
                match = re.fullmatch(r'(p[0-9]{4})-' + re.escape(phase.replace('_', '-')) + r'\.intent\.json', name)
                if match and value == evidence['intent_sha256']:
                    complete_name = match[1] + '-' + phase.replace('_', '-') + '.complete.json'
                    if retained.get(complete_name) == evidence['completion_sha256']:
                        candidates.append(match[1])
            _need(len(candidates) == 1 and (phase_prefix is None or phase_prefix == candidates[0]),
                  'RECOVERY_PHASE_ROLE_OR_ATTEMPT_CHANGED')
            phase_prefix = candidates[0]
            result = evidence['result']
            _need(type(result) is dict and result.get('plan_sha256') == digest(plan_raw), 'RECOVERY_PHASE_PLAN_CHANGED')
            fields = {
                'prepare': {'plan_sha256', 'job_id', 'source_manifest_sha256', 'package_sha256', 'operator_code_sha256'},
                'clean_check': {'state', 'plan_sha256'},
                'qa_stage': {'status', 'plan_sha256', 'source_sha256', 'allocation_receipt_sha256', 'image_id'},
                'qa_run': {'status', 'exit_code', 'plan_sha256', 'source_sha256', 'image_id'},
                'qa_collect': {'status', 'plan_sha256', 'source_sha256', 'collection_manifest_sha256'},
            }.get(phase, {'state', 'action', 'plan_sha256', 'evidence_sha256'})
            _need(set(result) == fields, 'RECOVERY_PHASE_FIELDS_CHANGED')
            if phase == 'prepare':
                _need(all(result.get(key) == value for key, value in identity.items())
                      and result['operator_code_sha256'] == plan['operator_code_sha256'], 'RECOVERY_PREPARE_CHANGED')
            elif phase == 'clean_check':
                _need(result.get('state') == 'PREPARED', 'RECOVERY_CLEAN_CHECK_UNRESOLVED')
            elif phase in ('allocate', 'schema', 'import', 'verify'):
                _need(result.get('state') == ('QA_READY' if phase == 'verify' else 'PHASE_COMPLETE')
                      and result.get('action') in ('COMPLETED_ONCE', 'ALREADY_COMPLETE_NO_REPLAY')
                      and _sha(result.get('evidence_sha256')), 'RECOVERY_CLEAN_PHASE_UNRESOLVED')
                if phase in ('allocate', 'verify'):
                    _need(result['evidence_sha256'] == digest(files['allocation-receipt.json' if phase == 'allocate' else 'clean-import-receipt.json']),
                          'RECOVERY_CLEAN_PHASE_CHANGED')
            else:
                _need(result.get('source_sha256') == collection.get('source_sha256'), 'RECOVERY_QA_SOURCE_CHANGED')
                if phase != 'qa_collect':
                    _need('sha256:' + str(result.get('image_id')).removeprefix('sha256:') == image,
                          'RECOVERY_PHASE_IMAGE_CHANGED')
                if phase == 'qa_stage':
                    _need(result.get('status') == 'STAGED' and result.get('allocation_receipt_sha256') == hashes['allocation_receipt_sha256'],
                          'RECOVERY_QA_STAGE_UNRESOLVED')
                elif phase == 'qa_run':
                    _need(result.get('status') == 'QA_FAILED_OR_INCOMPLETE'
                          and type(result.get('exit_code')) is int and result['exit_code'] == 2, 'RECOVERY_QA_OUTCOME_UNKNOWN')
                else:
                    _need(result.get('status') == 'COLLECTED' and result.get('collection_manifest_sha256') == digest(collection_raw),
                          'RECOVERY_QA_COLLECTION_UNRESOLVED')
        if type(producer) is dict and producer.get('scope') in {SYNCHRONOUS_SCOPE, SYNCHRONOUS_INVENTORY_SCOPE}:
            links = _synchronous_links(files=files, stage=stage, collection=collection, summary=summary,
                reviewed=reviewed_synchronous_launch, wrapper_raw=wrapper_raw)
            validator = (_synchronous_inventory_producer if producer['scope'] == SYNCHRONOUS_INVENTORY_SCOPE
                         else _synchronous_producer)
            validator(producer, binding, summary['session_id'], qa_id, image, now,
                reviewed=reviewed_synchronous_launch, links=links, finished=finished)
        else:
            _need(reviewed_synchronous_launch is None and wrapper_raw is None, 'RECOVERY_PRODUCER_VARIANTS_MIXED')
            _producer(producer, binding, summary['session_id'], qa_id, image, now, finished)
        return {'schema_version': 1, 'scope': DISPOSITION_SCOPE, 'failure_class': 'TERMINAL_QA_FAILED',
                'binding': binding.payload(), 'claim_sha256': summary['claim_sha256'], 'session_id': summary['session_id'],
                'qa_run_id': qa_id, 'plan_sha256': digest(plan_raw), 'collection_manifest_sha256': digest(collection_raw),
                'qa_report_sha256': digest(files['qa-result.json']),
                'allocation_receipt_sha256': hashes['allocation_receipt_sha256'], 'verification_profile_sha256': policy.sha256,
                'journal_summary_sha256': digest(canonical_bytes(summary)),
                'evidence_sha256': {name: digest(value) for name, value in files.items()}, 'producer': deepcopy_json(producer),
                'human_acceptance_recorded': False, 'automatic_retry_permitted': False}
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError('RECOVERY_FAILED_EVIDENCE_INVALID') from None


def deepcopy_json(value):
    return json.loads(canonical_bytes(value))


def _disposition(value):
    _need(type(value) is dict and set(value) == _DISPOSITION_KEYS, 'RECOVERY_DISPOSITION_FIELDS')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and value['scope'] == DISPOSITION_SCOPE and value['failure_class'] == 'TERMINAL_QA_FAILED'
          and value['human_acceptance_recorded'] is False and value['automatic_retry_permitted'] is False,
          'RECOVERY_DISPOSITION_INVALID')
    VerificationBinding.from_payload(value['binding'])
    _need(all(_sha(value[key]) for key in ('claim_sha256', 'plan_sha256', 'collection_manifest_sha256',
              'qa_report_sha256', 'allocation_receipt_sha256', 'verification_profile_sha256', 'journal_summary_sha256'))
          and type(value['evidence_sha256']) is dict and set(value['evidence_sha256']) == FILES
          and all(_sha(item) for item in value['evidence_sha256'].values()), 'RECOVERY_DISPOSITION_DIGEST_INVALID')
    return value


def disposition_sha256(value):
    return digest(canonical_bytes(_disposition(value)))


def make_retry_request(disposition, *, request_id, attempt_id, verifier_release_sha256):
    old = VerificationBinding.from_payload(_disposition(disposition)['binding'])
    _need(verifier_release_sha256 != old.verifier_release_sha256, 'RECOVERY_NEW_RETRY_RELEASE_REQUIRED')
    return validate_retry_request({'schema_version': 1, 'scope': RETRY_SCOPE, 'request_id': request_id,
        'attempt_id': attempt_id, 'disposition_sha256': disposition_sha256(disposition),
        'binding': {**old.payload(), 'verifier_release_sha256': verifier_release_sha256},
        'explicit_operator_authorization': True, 'automatic_retry_permitted': False})


def validate_retry_request(value):
    _need(type(value) is dict and set(value) == {'schema_version', 'scope', 'request_id', 'attempt_id',
          'disposition_sha256', 'binding', 'explicit_operator_authorization', 'automatic_retry_permitted'},
          'RECOVERY_RETRY_FIELDS')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == RETRY_SCOPE
          and type(value['request_id']) is str and _REQUEST.fullmatch(value['request_id'])
          and type(value['attempt_id']) is str and _ATTEMPT.fullmatch(value['attempt_id'])
          and _sha(value['disposition_sha256']) and value['explicit_operator_authorization'] is True
          and value['automatic_retry_permitted'] is False, 'RECOVERY_RETRY_INVALID')
    VerificationBinding.from_payload(value['binding'])
    return deepcopy_json(value)


@dataclass(frozen=True)
class ClosedFailure:
    binding: VerificationBinding
    disposition_sha256: str
    legacy_record_sha256: str


@dataclass(frozen=True)
class RetryClaim:
    attempt_id: str
    binding: VerificationBinding
    attempt_token: str = field(repr=False)


def admission_status(run, legacy_record, closed_failure=None, retry=None):
    """Shared pure predicate for future admission/status integration.

    Supply only store-validated ClosedFailure and retry projections. Unknown,
    inconsistent or active work stays blocking. This never grants acceptance.
    Call within the same BEGIN IMMEDIATE as ordinary admission/reservation.
    """
    blocked = {'blocks_admission': True, 'recovery_state': 'unresolved', 'retry_eligible': False}
    try:
        _need(type(run) is dict and type(run.get('id')) is str, 'RECOVERY_RUN_REQUIRED')
        if retry is not None:
            _need(type(retry) is dict and retry['binding']['job_id'] == run['id'], 'RECOVERY_RETRY_CHANGED')
            if retry['state'] in {'reserved', 'running', 'attention'}:
                return {**blocked, 'recovery_state': 'retry_' + retry['state']}
            _need(retry['state'] == 'completed' and run['state'] in {'VERIFIED', 'ACCEPTED'},
                  'RECOVERY_RETRY_INCONSISTENT')
        if run['state'] in {'QUEUED', 'PROCESSING'}:
            return {**blocked, 'recovery_state': 'conversion_active'}
        legacy = VerificationQueue._record(legacy_record) if legacy_record is not None else None
        if legacy is not None:
            _need(legacy['job_id'] == run['id'] and legacy['source_manifest_sha256'] == run['source_hash'],
                  'RECOVERY_LEGACY_BINDING_CHANGED')
        if run['state'] == 'QA_REQUIRED':
            if type(closed_failure) is ClosedFailure and legacy is not None:
                _need(legacy['state'] == 'attention' and legacy['proof_sha256'] is None
                      and legacy['record_sha256'] == closed_failure.legacy_record_sha256
                      and all(legacy[key] == value for key, value in closed_failure.binding.payload().items()),
                      'RECOVERY_CLOSED_FAILURE_CHANGED')
                return {'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': retry is None}
            return blocked
        if run['state'] not in {'VERIFIED', 'ACCEPTED', 'REVIEW_REQUIRED'}:
            return blocked
        if legacy is not None and legacy['state'] in {'queued', 'running', 'attention'} and closed_failure is None:
            return blocked
        return {'blocks_admission': False, 'recovery_state': 'no_active_verification', 'retry_eligible': False}
    except Exception:
        return blocked


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Explicit recovery initialization; never migration, repair or admission.

    The caller owns its connection and transaction. Preserve the public store's
    pre-write validation here as well: missing fences and partial tables must
    fail before CREATE IF NOT EXISTS could silently repair them.
    """
    names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    present = names & set(VerificationRecovery._TABLES)
    _need(not present or present in (set(VerificationRecovery._TABLES),
          set(VerificationRecovery._TABLES) - {_OBSERVATION_TABLE}), 'RECOVERY_PARTIAL_SCHEMA')
    if present:
        VerificationRecovery.validate_schema(connection)
    connection.execute('SELECT job_id,record_sha256,claim_token FROM verification_queue LIMIT 0')
    connection.execute('SELECT id,source_hash,state,artifact FROM runs LIMIT 0')
    _need(not present or _OBSERVATION_TABLE in names,
          'RECOVERY_EXPLICIT_OBSERVATION_MIGRATION_REQUIRED')
    for sql in VerificationRecovery.schema_definitions().values():
        connection.execute(sql)
    VerificationRecovery.validate_schema(connection)


class VerificationRecovery:
    """Explicit protected-local store. Default construction performs no I/O.

    producer_probe(binding, session_id, qa_run_id) must perform an authoritative
    stopped-producer observation under the operator's exclusion lock. There is
    deliberately no built-in network transport or caller-JSON fallback.
    """
    _TABLES = {
        'verification_failed_dispositions': ('disposition_sha256', 'job_id', 'legacy_record_sha256',
            'claim_sha256', 'disposition_raw', 'recorded_at_utc', 'record_sha256'),
        'verification_retry_attempts': ('attempt_id', 'request_id', 'disposition_sha256', 'job_id',
            'request_raw', 'request_sha256', 'created_at_utc', 'record_sha256'),
        'verification_retry_events': ('attempt_id', 'sequence', 'state', 'payload_raw',
            'previous_sha256', 'recorded_at_utc', 'record_sha256'),
        _OBSERVATION_TABLE: ('observation_sha256', 'disposition_sha256', 'purpose',
            'verifier_release_sha256', 'attempt_id', 'observation_raw', 'recorded_at_utc', 'record_sha256'),
    }
    _DDL = {
        'verification_failed_dispositions': '''CREATE TABLE IF NOT EXISTS verification_failed_dispositions(
            disposition_sha256 TEXT PRIMARY KEY,job_id TEXT NOT NULL UNIQUE REFERENCES verification_queue(job_id),
            legacy_record_sha256 TEXT NOT NULL,claim_sha256 TEXT NOT NULL,disposition_raw BLOB NOT NULL,
            recorded_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)''',
        'verification_retry_attempts': '''CREATE TABLE IF NOT EXISTS verification_retry_attempts(
            attempt_id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,
            disposition_sha256 TEXT NOT NULL UNIQUE REFERENCES verification_failed_dispositions(disposition_sha256),
            job_id TEXT NOT NULL REFERENCES runs(id),request_raw BLOB NOT NULL,request_sha256 TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)''',
        'verification_retry_events': '''CREATE TABLE IF NOT EXISTS verification_retry_events(
            attempt_id TEXT NOT NULL REFERENCES verification_retry_attempts(attempt_id),sequence INTEGER NOT NULL,
            state TEXT NOT NULL,payload_raw BLOB NOT NULL,previous_sha256 TEXT NOT NULL,
            recorded_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL,PRIMARY KEY(attempt_id,sequence))''',
        _OBSERVATION_TABLE: '''CREATE TABLE IF NOT EXISTS verification_producer_observations(
            observation_sha256 TEXT PRIMARY KEY,
            disposition_sha256 TEXT NOT NULL REFERENCES verification_failed_dispositions(disposition_sha256),
            purpose TEXT NOT NULL,verifier_release_sha256 TEXT NOT NULL,
            attempt_id TEXT REFERENCES verification_retry_attempts(attempt_id),observation_raw BLOB NOT NULL,
            recorded_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)''',
    }

    @classmethod
    def schema_definitions(cls, *, include_observations=True):
        """Exact reviewed owned definitions, including fence bodies."""
        tables = set(cls._TABLES) - (set() if include_observations else {_OBSERVATION_TABLE})
        definitions = {('table', name): sql for name, sql in cls._DDL.items() if name in tables}
        for table in sorted(tables):
            for action in ('UPDATE', 'DELETE'):
                name = table + '_no_' + action.lower()
                definitions[('trigger', name)] = (
                    'CREATE TRIGGER IF NOT EXISTS ' + name + ' BEFORE ' + action + ' ON ' + table
                    + " BEGIN SELECT RAISE(ABORT,'RECOVERY_APPEND_ONLY'); END")
        for action in ('UPDATE', 'DELETE'):
            name = 'verification_closed_legacy_no_' + action.lower()
            definitions[('trigger', name)] = (
                'CREATE TRIGGER IF NOT EXISTS ' + name + ' BEFORE ' + action
                + ' ON verification_queue WHEN EXISTS '
                '(SELECT 1 FROM verification_failed_dispositions WHERE job_id=OLD.job_id) '
                "BEGIN SELECT RAISE(ABORT,'RECOVERY_LEGACY_HISTORY_IMMUTABLE'); END")
        return definitions

    @staticmethod
    def normalized_schema_sql(sql):
        _need(type(sql) is str and 0 < len(sql) <= 16_384, 'RECOVERY_SCHEMA_DEFINITION_INVALID')
        sql = sql.strip()
        for kind in ('TABLE', 'TRIGGER'):
            prefix = 'CREATE ' + kind + ' IF NOT EXISTS '
            if sql.startswith(prefix):
                sql = 'CREATE ' + kind + ' ' + sql[len(prefix):]
                break
        return ' '.join(sql.split())

    @classmethod
    def validate_schema(cls, db):
        """Read-only metadata validation, never a write probe or repair."""
        rows = list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','trigger')"))
        present = {row[1] for row in rows if row[0] == 'table'} & set(cls._TABLES)
        legacy = set(cls._TABLES) - {_OBSERVATION_TABLE}
        _need(present in (legacy, set(cls._TABLES)), 'RECOVERY_PARTIAL_SCHEMA')
        expected = cls.schema_definitions(include_observations=_OBSERVATION_TABLE in present)
        actual = {(row[0], row[1]): row[3] for row in rows}
        for key, sql in expected.items():
            _need(key in actual and cls.normalized_schema_sql(actual[key]) == cls.normalized_schema_sql(sql),
                  'RECOVERY_SCHEMA_OR_FENCE_DEFINITION_CHANGED')
        owned = set(cls._TABLES) | {'verification_queue'}
        _need({('trigger', row[1]) for row in rows if row[0] == 'trigger' and row[2] in owned}
              == {key for key in expected if key[0] == 'trigger'}, 'RECOVERY_UNREVIEWED_TRIGGER')
        for table, columns in cls._TABLES.items():
            if table not in present:
                continue
            _need(tuple(row[1] for row in db.execute('PRAGMA table_info(' + table + ')')) == columns,
                  'RECOVERY_SCHEMA_CHANGED')

    def __init__(self, database, *, enabled=False, producer_probe=None, approved_retry_releases=(),
                 approved_synchronous_launches=(), observation_probe=None,
                 current_verifier_release_sha256=None):
        _need(type(enabled) is bool, 'RECOVERY_ENABLE_INVALID')
        _need(type(approved_retry_releases) in (tuple, list, set, frozenset)
              and all(_sha(value) for value in approved_retry_releases), 'RECOVERY_APPROVED_RELEASES_INVALID')
        _need(producer_probe is None or callable(producer_probe), 'RECOVERY_PROBE_INVALID')
        _need(observation_probe is None or callable(observation_probe), 'RECOVERY_OBSERVATION_PROBE_INVALID')
        _need(current_verifier_release_sha256 is None or _sha(current_verifier_release_sha256),
              'RECOVERY_CURRENT_RELEASE_INVALID')
        _need(type(approved_synchronous_launches) in (tuple, list, set, frozenset)
              and all(type(value) is ReviewedSynchronousLaunch for value in approved_synchronous_launches),
              'RECOVERY_REVIEWED_LAUNCH_INVALID')
        _need(len(set(approved_synchronous_launches)) == len(approved_synchronous_launches),
              'RECOVERY_REVIEWED_LAUNCH_DUPLICATED')
        self.database = Path(database).absolute()
        self.enabled, self.producer_probe = enabled, producer_probe
        self.approved_retry_releases = frozenset(approved_retry_releases)
        # Protected release configuration only, never derived from request JSON.
        self.approved_synchronous_launches = tuple(approved_synchronous_launches)
        # Set only by a protected adapter which attests the CURRENT runtime and
        # holds its exclusion lease. Neither this string nor JSON is attestation.
        self.current_verifier_release_sha256 = current_verifier_release_sha256
        self.observation_probe = observation_probe

    @contextmanager
    def _db(self, write=False):
        _need(self.enabled, 'RECOVERY_DISABLED')
        _need(self.database.is_file() and not self.database.is_symlink()
              and self.database.resolve() == self.database, 'RECOVERY_DATABASE_UNSAFE')
        db = None
        try:
            db = sqlite3.connect(self.database.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                 uri=True, timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            if write:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
            # Existing recovery metadata is never silently repaired or trusted
            # by name alone, including direct lookup/record/complete calls.
            self._recovery_available(db)
            yield db
            if write:
                db.commit()
        except sqlite3.Error:
            raise RecoveryError('RECOVERY_STORAGE_UNAVAILABLE') from None
        finally:
            if db is not None:
                if db.in_transaction:
                    db.rollback()
                db.close()

    def initialize(self):
        with self._db(True) as db:
            initialize_schema(db)

    def migrate_observation_ledger(self):
        """Explicit atomic transition from the exact reviewed three-table store.

        Never called by a read or normal recovery operation. Existing schema
        definitions and fences are validated before adding only the new table
        and its fences; old rows are preserved, not certified as rollout-ready.
        """
        with self._db(True) as db:
            self.validate_schema(db)
            names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if _OBSERVATION_TABLE in names:
                return {'status': 'OBSERVATION_LEDGER_READY', 'migrated': False}
            old = self.schema_definitions(include_observations=False)
            for key, sql in self.schema_definitions().items():
                if key not in old:
                    db.execute(sql)
            self.validate_schema(db)
            return {'status': 'OBSERVATION_LEDGER_READY', 'migrated': True}

    @staticmethod
    def _record_hash(row):
        return digest(canonical_bytes({key: (digest(value) if type(value) is bytes else value)
                                       for key, value in row.items() if key != 'record_sha256'}))

    @classmethod
    def _insert(cls, db, table, row):
        _need(table in cls._TABLES and set(row) == set(cls._TABLES[table]) - {'record_sha256'},
              'RECOVERY_RECORD_FIELDS')
        row = {**row, 'record_sha256': cls._record_hash(row)}
        db.execute('INSERT INTO ' + table + ' VALUES(' + ','.join('?' for _ in row) + ')',
                   tuple(row[key] for key in cls._TABLES[table]))
        return row

    @classmethod
    def _checked_record(cls, table, row):
        _need(row is not None, 'RECOVERY_RECORD_MISSING')
        value = dict(row)
        _need(set(value) == set(cls._TABLES[table]) and value['record_sha256'] == cls._record_hash(value),
              'RECOVERY_RECORD_CHANGED')
        return value

    def _server_run(self, db, binding, *, unverified):
        run = VerificationQueue._run(db, binding, states={'QA_REQUIRED'} if unverified else {'QA_REQUIRED', 'VERIFIED', 'ACCEPTED'})
        job = self.database.parent / 'jobs' / binding.job_id
        package = job / 'apex-package.zip'
        _need(package.is_file() and not package.is_symlink() and package.resolve() == package
              and 0 < package.stat().st_size <= 8_000_000, 'RECOVERY_RETAINED_PACKAGE_CHANGED')
        package_raw = package.read_bytes()
        _need(digest(package_raw) == binding.package_sha256,
              'RECOVERY_RETAINED_PACKAGE_CHANGED')
        documents = []
        for name in ('source-snapshot.json', 'release-evidence.json'):
            path = job / name
            _need(path.is_file() and not path.is_symlink() and path.resolve() == path
                  and 0 < path.stat().st_size <= 2_000_000, 'RECOVERY_RETAINED_SOURCE_UNAVAILABLE')
            documents.append(_load(path.read_bytes()))
        snapshot, release = documents
        # Retained project identity selects its own cache. Never recover a
        # project by interpreting its package as a historical single form.
        from .verification_runtime import _handoff_profile, _project_handoff, VerificationRuntimeError
        try:
            profile, pipeline = _handoff_profile(job, snapshot, release)
            path = job / pipeline / 'download.json'
            _need(path.is_file() and not path.is_symlink() and path.resolve() == path
                  and 0 < path.stat().st_size <= 16_384, 'RECOVERY_RETAINED_SOURCE_UNAVAILABLE')
            download = _load(path.read_bytes())
            if profile == 'native-project-v1':
                _need(run.get('project') == snapshot.get('project_id') == snapshot.get('project'),
                      'RECOVERY_RETAINED_SOURCE_CHANGED')
                _project_handoff(job, snapshot, release, package_raw)
                package_digest = digest(package_raw)
            else:
                package_digest = verify_package(package_raw, release, snapshot.get('native_form'))
        except VerificationRuntimeError:
            raise RecoveryError('RECOVERY_RETAINED_SOURCE_CHANGED') from None
        files = snapshot.get('files')
        _need(type(files) is list and 0 < len(files) <= 50, 'RECOVERY_RETAINED_SOURCE_CHANGED')
        checked = []
        for item in files:
            encoded = item['text'].encode('utf-8')
            original = encoded if digest(encoded) == item['sha256'] else b'\xef\xbb\xbf' + encoded
            value = checked_source(item['name'], original)
            _need(all(value[key] == item[key] for key in ('name', 'text', 'bytes', 'sha256')),
                  'RECOVERY_RETAINED_SOURCE_CHANGED')
            checked.append(value)
        _need(len({item['name'] for item in checked}) == len(checked)
              and sum(len(item['text'].encode('utf-8')) for item in checked) <= MAX_CONVERSION_BYTES
              and inventory(checked)['source_hash'] == snapshot.get('source_hash') == binding.source_manifest_sha256
              and all(snapshot.get('approvals', {}).get(key) is True
                      for key in ('redacted_source', 'external_ai', 'synthetic_prototype'))
              and release.get('job_id') == binding.job_id
              and release.get('source_manifest_sha256') == binding.source_manifest_sha256
              and download == {'source_hash': binding.source_manifest_sha256, 'package_sha256': binding.package_sha256}
              and package_digest == binding.package_sha256,
              'RECOVERY_RETAINED_SOURCE_CHANGED')
        if run['state'] in {'VERIFIED', 'ACCEPTED'}:
            from .technical_release import checked_release, VerificationError
            try:
                checked_release_value = checked_release(db, self.database.parent, run)
                _need(checked_release_value is not None
                      and digest(checked_release_value['package']) == binding.package_sha256,
                      'RECOVERY_TECHNICAL_PROOF_CHANGED')
            except VerificationError:
                raise RecoveryError('RECOVERY_TECHNICAL_PROOF_CHANGED') from None
        if unverified:
            _need(db.execute('SELECT COUNT(*) FROM acceptances WHERE run=?', (binding.job_id,)).fetchone()[0] == 0,
                  'RECOVERY_ACCEPTANCE_EXISTS')
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
            _need(not exists or db.execute('SELECT COUNT(*) FROM technical_verifications WHERE run=?',
                                          (binding.job_id,)).fetchone()[0] == 0, 'RECOVERY_TECHNICAL_PROOF_EXISTS')
        return run

    def _closed(self, db, job_id):
        row = db.execute('SELECT * FROM verification_failed_dispositions WHERE job_id=?', (job_id,)).fetchone()
        if row is None:
            return None, None
        record = self._checked_record('verification_failed_dispositions', row)
        document = _disposition(_load(record['disposition_raw']))
        _need(canonical_bytes(document) == record['disposition_raw']
              and disposition_sha256(document) == record['disposition_sha256']
              and record['job_id'] == document['binding']['job_id']
              and record['claim_sha256'] == document['claim_sha256'], 'RECOVERY_CLOSED_DOCUMENT_CHANGED')
        legacy = VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (job_id,)).fetchone())
        _need(legacy is not None and legacy['state'] == 'attention'
              and legacy['record_sha256'] == record['legacy_record_sha256']
              and legacy['proof_sha256'] is None, 'RECOVERY_LEGACY_HISTORY_CHANGED')
        binding = VerificationBinding.from_payload(document['binding'])
        _need(all(legacy[key] == value for key, value in binding.payload().items())
              and claim_sha256(Claim(binding, legacy['claim_token'])) == document['claim_sha256'],
              'RECOVERY_ORIGINAL_CLAIM_CHANGED')
        self._server_run(db, binding, unverified=False)
        if document['producer'].get('scope') == SYNCHRONOUS_INVENTORY_SCOPE:
            # A v2 closure is not readable/admissible without its separately
            # retained authoritative observation. The same path is used by
            # historical readers, admission, retry and direct lookups; none may
            # treat schema presence or the original disposition as that proof.
            _need(_OBSERVATION_TABLE in {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")},
                'RECOVERY_V2_OBSERVATION_LEDGER_MISSING')
            rows = list(db.execute('SELECT * FROM ' + _OBSERVATION_TABLE +
                ' WHERE disposition_sha256=? ORDER BY recorded_at_utc,observation_sha256 LIMIT 129',
                (record['disposition_sha256'],)))
            _need(0 < len(rows) <= 128, 'RECOVERY_V2_OBSERVATION_LEDGER_MISSING_OR_UNBOUNDED')
            checked = [self._checked_observation(db, item, document) for item in rows]
            _need(any(item['purpose'] == 'failure_disposition' and item['attempt_id'] is None
                      for item in checked), 'RECOVERY_INITIAL_OBSERVATION_MISSING')
        return ClosedFailure(binding, record['disposition_sha256'], record['legacy_record_sha256']), document

    def _reviewed_launch(self, document):
        producer = document['producer']
        _need(type(producer) is dict, 'RECOVERY_PRODUCER_FIELDS')
        if producer.get('scope') not in {SYNCHRONOUS_SCOPE, SYNCHRONOUS_INVENTORY_SCOPE}:
            return None
        matches = [item for item in self.approved_synchronous_launches
            if item.verifier_release_sha256 == document['binding']['verifier_release_sha256']
            and item.qa_source_sha256 == producer.get('qa_source_sha256')
            and item.wrapper_sha256 == producer.get('wrapper_sha256')
            and item.original_wrapper_sha256 == producer.get('original_wrapper_sha256')
            and item.image_id == producer.get('image_id')]
        _need(len(matches) == 1, 'RECOVERY_REVIEWED_SYNCHRONOUS_LAUNCH_REQUIRED')
        return matches[0]

    def _observe(self, document, now):
        _need(self.producer_probe is not None, 'RECOVERY_AUTHORITATIVE_PROBE_REQUIRED')
        binding = VerificationBinding.from_payload(document['binding'])
        try:
            observed = self.producer_probe(binding, document['session_id'], document['qa_run_id'])
        except Exception:
            raise RecoveryError('RECOVERY_AUTHORITATIVE_PROBE_UNAVAILABLE') from None
        original = document['producer']
        reviewed = self._reviewed_launch(document)
        if reviewed is not None:
            validator = (_synchronous_inventory_producer if original.get('scope') == SYNCHRONOUS_INVENTORY_SCOPE
                         else _synchronous_producer)
            validator(observed, binding, document['session_id'], document['qa_run_id'],
                original['image_id'], now, reviewed=reviewed,
                links={key: original[key] for key in _SYNCHRONOUS_LINKS})
        else:
            _producer(observed, binding, document['session_id'], document['qa_run_id'], original['image_id'], now)
        _need(producer_identity(observed) == producer_identity(original),
              'RECOVERY_PRODUCER_IDENTITY_CHANGED')
        return observed

    def _observation_context(self, db, document, purpose, release, attempt_id, *, writing):
        _need(_OBSERVATION_TABLE in {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")},
            'RECOVERY_OBSERVATION_LEDGER_MIGRATION_REQUIRED')
        _need(type(purpose) is str and purpose in OBSERVATION_PURPOSES and _sha(release),
              'RECOVERY_OBSERVATION_CONTEXT_INVALID')
        _need(document['producer'].get('scope') == SYNCHRONOUS_INVENTORY_SCOPE,
              'RECOVERY_V2_ORIGINAL_OBSERVATION_REQUIRED')
        if writing:
            _need(release == self.current_verifier_release_sha256,
                  'RECOVERY_CURRENT_RELEASE_CHANGED')
            self._server_run(db, VerificationBinding.from_payload(document['binding']), unverified=True)
        if purpose == 'failure_disposition':
            _need(attempt_id is None, 'RECOVERY_OBSERVATION_ATTEMPT_INVALID')
            if writing:
                _need(db.execute('SELECT 1 FROM verification_retry_attempts WHERE disposition_sha256=?',
                                  (disposition_sha256(document),)).fetchone() is None,
                      'RECOVERY_OBSERVATION_RETRY_CONTEXT_REQUIRED')
        else:
            _need(type(attempt_id) is str and _ATTEMPT.fullmatch(attempt_id),
                  'RECOVERY_OBSERVATION_ATTEMPT_INVALID')
            attempt = self._attempt(db, attempt_id)
            _need(attempt is not None and attempt['disposition_sha256'] == disposition_sha256(document)
                  and attempt['binding']['verifier_release_sha256'] == release
                  and all(attempt['binding'][key] == document['binding'][key]
                          for key in ('job_id', 'source_manifest_sha256', 'package_sha256'))
                  and (not writing or attempt['state'] == 'reserved'),
                  'RECOVERY_OBSERVATION_ATTEMPT_CHANGED')

    def _validate_observation(self, document, observed, now, *, writing):
        original = document['producer']
        if writing:
            reviewed = self._reviewed_launch(document)
        else:
            # A historical read checks its retained identity, not whether that
            # old launcher is approved for use by the current installation.
            reviewed = ReviewedSynchronousLaunch(document['binding']['verifier_release_sha256'],
                original['qa_source_sha256'], original['wrapper_sha256'],
                original['original_wrapper_sha256'], original['image_id'])
        _synchronous_inventory_producer(observed, VerificationBinding.from_payload(document['binding']),
            document['session_id'], document['qa_run_id'], original['image_id'], now,
            reviewed=reviewed, links={key: original[key] for key in _SYNCHRONOUS_LINKS})
        _need(producer_identity(observed) == producer_identity(original),
              'RECOVERY_PRODUCER_IDENTITY_CHANGED')

    @staticmethod
    def _observation_sha(document_sha, purpose, release, attempt_id, raw):
        return digest(canonical_bytes({'disposition_sha256': document_sha, 'purpose': purpose,
            'verifier_release_sha256': release, 'attempt_id': attempt_id,
            'observation_raw_sha256': digest(raw)}))

    def _append_observation(self, db, document, *, purpose, attempt_id=None, raw=None, now=None):
        release = self.current_verifier_release_sha256
        self._observation_context(db, document, purpose, release, attempt_id, writing=True)
        _need(self.observation_probe is not None, 'RECOVERY_ATTESTED_OBSERVATION_PROBE_REQUIRED')
        try:
            observed = self.observation_probe(release, VerificationBinding.from_payload(document['binding']),
                document['session_id'], document['qa_run_id'], purpose, attempt_id)
        except Exception:
            raise RecoveryError('RECOVERY_ATTESTED_OBSERVATION_UNAVAILABLE') from None
        self._validate_observation(document, observed, _clock(now), writing=True)
        authoritative_raw = canonical_bytes(observed)
        _need(raw is None or type(raw) is bytes and raw == authoritative_raw,
              'RECOVERY_EXACT_ATTESTED_OBSERVATION_REQUIRED')
        raw = authoritative_raw
        document_sha = disposition_sha256(document)
        sha = self._observation_sha(document_sha, purpose, release, attempt_id, raw)
        prior = db.execute('SELECT * FROM ' + _OBSERVATION_TABLE + ' WHERE observation_sha256=?',
                           (sha,)).fetchone()
        if prior is not None:
            checked = self._checked_observation(db, prior, document)
            return {'status': 'OBSERVATION_RECORDED', 'observation_sha256': sha,
                    'observation': checked, 'idempotent': True}
        _need(db.execute('SELECT COUNT(*) FROM ' + _OBSERVATION_TABLE +
                         ' WHERE disposition_sha256=?', (document_sha,)).fetchone()[0] < 128,
              'RECOVERY_OBSERVATION_LEDGER_LIMIT_REACHED')
        row = self._insert(db, _OBSERVATION_TABLE, {'observation_sha256': sha,
            'disposition_sha256': document_sha, 'purpose': purpose, 'verifier_release_sha256': release,
            'attempt_id': attempt_id, 'observation_raw': raw, 'recorded_at_utc': _clock(now).isoformat()})
        return {'status': 'OBSERVATION_RECORDED', 'observation_sha256': sha,
                'observation': self._checked_observation(db, row, document), 'idempotent': False}

    def _checked_observation(self, db, row, document):
        row = self._checked_record(_OBSERVATION_TABLE, row)
        raw = row['observation_raw']
        observed = _load(raw, 65_536)
        _need(raw == canonical_bytes(observed) and row['disposition_sha256'] == disposition_sha256(document)
              and row['observation_sha256'] == self._observation_sha(row['disposition_sha256'], row['purpose'],
                  row['verifier_release_sha256'], row['attempt_id'], raw), 'RECOVERY_OBSERVATION_CHANGED')
        self._observation_context(db, document, row['purpose'], row['verifier_release_sha256'],
                                  row['attempt_id'], writing=False)
        self._validate_observation(document, observed,
            datetime.fromtimestamp(_time(row['recorded_at_utc']), timezone.utc), writing=False)
        return {**row, 'producer': observed}

    def record_observation(self, disposition_sha256, observation_raw, *, purpose,
                           verifier_release_sha256, attempt_id=None, now=None):
        """Explicit protected append; caller bytes never replace live attestation."""
        _need(_sha(disposition_sha256) and verifier_release_sha256 == self.current_verifier_release_sha256,
              'RECOVERY_OBSERVATION_BINDING_INVALID')
        _need(type(observation_raw) is bytes and 0 < len(observation_raw) <= 65_536,
              'RECOVERY_INPUT_BOUNDS')
        with self._db(True) as db:
            row = db.execute('SELECT job_id FROM verification_failed_dispositions WHERE disposition_sha256=?',
                             (disposition_sha256,)).fetchone()
            _need(row is not None, 'RECOVERY_CLOSED_FAILURE_REQUIRED')
            _, document = self._closed(db, row['job_id'])
            return self._append_observation(db, document, purpose=purpose, attempt_id=attempt_id,
                                            raw=observation_raw, now=now)

    def read_observations(self, disposition_sha256):
        """Read-only retained witnesses; never probes, initializes or migrates."""
        _need(_sha(disposition_sha256), 'RECOVERY_DIGEST_REQUIRED')
        with self._db() as db:
            db.execute('BEGIN')
            if not self._recovery_available(db):
                return []
            row = db.execute('SELECT job_id FROM verification_failed_dispositions WHERE disposition_sha256=?',
                             (disposition_sha256,)).fetchone()
            if row is None:
                return []
            _, document = self._closed(db, row['job_id'])
            names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if _OBSERVATION_TABLE not in names:
                return []
            return [self._checked_observation(db, value, document) for value in db.execute(
                'SELECT * FROM ' + _OBSERVATION_TABLE + ' WHERE disposition_sha256=? '
                'ORDER BY recorded_at_utc,observation_sha256', (disposition_sha256,))]

    def record_failure(self, claim, disposition_raw, *, evidence, now=None):
        """Insert once; caller evidence alone cannot authorize this write."""
        _need(type(claim) is Claim, 'RECOVERY_ORIGINAL_CLAIM_REQUIRED')
        document = _disposition(_load(disposition_raw, 65_536))
        _need(disposition_raw == canonical_bytes(document)
              and document['binding'] == claim.binding.payload()
              and document['claim_sha256'] == claim_sha256(claim), 'RECOVERY_EXACT_DISPOSITION_REQUIRED')
        sha = digest(disposition_raw)
        with self._db(True) as db:
            prior = db.execute('SELECT * FROM verification_failed_dispositions WHERE job_id=?', (claim.binding.job_id,)).fetchone()
            if prior is not None:
                _, saved = self._closed(db, claim.binding.job_id)
                _need(canonical_bytes(saved) == disposition_raw, 'RECOVERY_DIFFERENT_DISPOSITION_EXISTS')
                return {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': sha, 'disposition': saved}
            reviewed = self._reviewed_launch(document)
            required = {'package', 'plan_raw', 'collection_raw', 'files', 'journal_summary'}
            if reviewed is not None:
                required.add('wrapper_raw')
            _need(type(evidence) is dict and set(evidence) == required,
                  'RECOVERY_EVIDENCE_ARGUMENTS')
            original_observation = _time(document['producer']['observed_at_utc'])
            _need(original_observation <= _clock(now).timestamp() + 5, 'RECOVERY_ORIGINAL_OBSERVATION_FUTURE')
            checked = validate_failed_evidence(binding=claim.binding, **evidence,
                producer=document['producer'], now=datetime.fromtimestamp(original_observation, timezone.utc),
                reviewed_synchronous_launch=reviewed)
            _need(canonical_bytes(checked) == disposition_raw, 'RECOVERY_DISPOSITION_EVIDENCE_CHANGED')
            legacy = VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?',
                                                          (claim.binding.job_id,)).fetchone())
            _need(legacy is not None and legacy['state'] == 'attention' and legacy['proof_sha256'] is None
                  and legacy['claim_token'] == claim.attempt_token
                  and all(legacy[key] == value for key, value in claim.binding.payload().items()),
                  'RECOVERY_LEGACY_ATTEMPT_UNRESOLVED')
            self._server_run(db, claim.binding, unverified=True)
            v2 = document['producer'].get('scope') == SYNCHRONOUS_INVENTORY_SCOPE
            if not v2:
                self._observe(document, _clock(now))
            self._insert(db, 'verification_failed_dispositions', {'disposition_sha256': sha,
                'job_id': claim.binding.job_id, 'legacy_record_sha256': legacy['record_sha256'],
                'claim_sha256': document['claim_sha256'], 'disposition_raw': disposition_raw,
                'recorded_at_utc': _clock(now).isoformat()})
            if v2:
                self._append_observation(db, document, purpose='failure_disposition', now=now)
        return {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': sha, 'disposition': document}

    def lookup_resolution(self, disposition_sha256):
        _need(_sha(disposition_sha256), 'RECOVERY_DIGEST_REQUIRED')
        with self._db() as db:
            row = db.execute('SELECT job_id FROM verification_failed_dispositions WHERE disposition_sha256=?',
                             (disposition_sha256,)).fetchone()
            if row is None:
                return None
            _, document = self._closed(db, row['job_id'])
            return {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': disposition_sha256, 'disposition': document}

    def _attempt(self, db, attempt_id, *, private=False):
        row = db.execute('SELECT * FROM verification_retry_attempts WHERE attempt_id=?', (attempt_id,)).fetchone()
        if row is None:
            return None
        saved = self._checked_record('verification_retry_attempts', row)
        request = validate_retry_request(_load(saved['request_raw'], 16_384))
        _need(canonical_bytes(request) == saved['request_raw'] and digest(saved['request_raw']) == saved['request_sha256']
              and all(request[key] == saved[key] for key in ('attempt_id', 'request_id', 'disposition_sha256'))
              and request['binding']['job_id'] == saved['job_id'], 'RECOVERY_RETRY_REQUEST_CHANGED')
        previous, state, token = '0' * 64, None, None
        events = list(db.execute('SELECT * FROM verification_retry_events WHERE attempt_id=? ORDER BY sequence', (attempt_id,)))
        _need(bool(events), 'RECOVERY_RETRY_EVENT_MISSING')
        for index, raw_event in enumerate(events):
            event = self._checked_record('verification_retry_events', raw_event)
            _need(event['sequence'] == index and event['previous_sha256'] == previous, 'RECOVERY_EVENT_CHAIN_CHANGED')
            payload = _load(event['payload_raw'], 16_384)
            next_state = event['state']
            if index == 0:
                _need(next_state == 'reserved' and payload == {'request_sha256': saved['request_sha256']},
                      'RECOVERY_RESERVATION_CHANGED')
            elif next_state == 'running':
                _need(state == 'reserved' and set(payload) == {'attempt_token'} and type(payload['attempt_token']) is str
                      and re.fullmatch(r'[a-f0-9]{32}', payload['attempt_token']), 'RECOVERY_RETRY_CLAIM_CHANGED')
                token = payload['attempt_token']
            elif next_state == 'attention':
                _need(state == 'running' and payload == {'code': 'OUTCOME_UNCONFIRMED'}, 'RECOVERY_RETRY_OUTCOME_UNKNOWN')
            else:
                _need(next_state == 'completed' and state in {'running', 'attention'}
                      and set(payload) == {'proof_sha256'} and _sha(payload['proof_sha256']), 'RECOVERY_COMPLETION_INVALID')
            state, previous = next_state, event['record_sha256']
        result = {'attempt_id': attempt_id, 'request_id': saved['request_id'], 'request_sha256': saved['request_sha256'],
                  'disposition_sha256': saved['disposition_sha256'], 'binding': request['binding'], 'state': state,
                  'created_at_utc': saved['created_at_utc']}
        if state == 'completed':
            result['proof_sha256'] = payload['proof_sha256']
        if private:
            result.update(attempt_token=token, sequence=len(events), last_event_sha256=previous)
        return result

    def _event(self, db, attempt_id, state, payload, now, current=None):
        return self._insert(db, 'verification_retry_events', {'attempt_id': attempt_id,
            'sequence': current['sequence'] if current else 0, 'state': state,
            'payload_raw': canonical_bytes(payload), 'previous_sha256': current['last_event_sha256'] if current else '0' * 64,
            'recorded_at_utc': _clock(now).isoformat()})

    def _eligibility(self, db, job_id):
        run = db.execute('SELECT * FROM runs WHERE id=?', (job_id,)).fetchone()
        _need(run is not None, 'RECOVERY_RUN_MISSING')
        legacy = db.execute('SELECT * FROM verification_queue WHERE job_id=?', (job_id,)).fetchone()
        available = self._recovery_available(db)
        closed, _ = self._closed(db, job_id) if available else (None, None)
        row = db.execute('SELECT attempt_id FROM verification_retry_attempts WHERE job_id=?', (job_id,)).fetchone() if available else None
        retry = self._attempt(db, row['attempt_id']) if row else None
        result = admission_status(dict(run), dict(legacy) if legacy else None, closed, retry)
        if retry is not None:
            retry_binding = VerificationBinding.from_payload(retry['binding'])
            _need(closed is not None and retry['disposition_sha256'] == closed.disposition_sha256
                  and retry_binding.verifier_release_sha256 != closed.binding.verifier_release_sha256
                  and all(getattr(retry_binding, key) == getattr(closed.binding, key)
                          for key in ('job_id', 'source_manifest_sha256', 'package_sha256')),
                  'RECOVERY_RETRY_HISTORY_LINK_CHANGED')
            if retry['state'] == 'completed':
                _need(not result['blocks_admission'] and run['state'] in {'VERIFIED', 'ACCEPTED'},
                      'RECOVERY_RETRY_COMPLETED_STATE_CHANGED')
                # A completed event or run-state string alone is never enough.
                # Recheck the real retained technical gate on every historical
                # readiness read, including all raw receipt/proof bindings.
                queue = VerificationQueue(self.database, enabled=True,
                                          verifier_release_sha256=retry_binding.verifier_release_sha256)
                queue._validated_proof(db, retry_binding, TechnicalProofResult(retry['proof_sha256']))
                return {'blocks_admission': False, 'recovery_state': 'retry_completed_verified',
                        'retry_eligible': False}
        return result

    def _recovery_available(self, db):
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        present = names & set(self._TABLES)
        _need(not present or present in (set(self._TABLES), set(self._TABLES) - {_OBSERVATION_TABLE}),
              'RECOVERY_PARTIAL_SCHEMA')
        if present:
            self.validate_schema(db)
        return bool(present)

    def _job_ids(self, db):
        query = 'SELECT id AS job_id FROM runs UNION SELECT job_id FROM verification_queue'
        if self._recovery_available(db):
            query += ' UNION SELECT job_id FROM verification_retry_attempts'
        return [row[0] for row in db.execute(query)]

    def _other_work_allows(self, db, *, except_job_id=None):
        return all(not self._eligibility(db, job_id)['blocks_admission']
                   for job_id in self._job_ids(db) if job_id != except_job_id)

    def _transaction(self, db):
        _need(self.enabled and db.in_transaction, 'RECOVERY_ADMISSION_TRANSACTION_REQUIRED')
        main = next((row for row in db.execute('PRAGMA database_list') if row[1] == 'main'), None)
        _need(main is not None and Path(main[2]).absolute() == self.database, 'RECOVERY_ADMISSION_DATABASE_CHANGED')

    def admission_allowed(self, db):
        """Read only inside the caller's existing BEGIN IMMEDIATE; no nested DB."""
        try:
            self._transaction(db)
            return self._other_work_allows(db)
        except Exception:
            return False

    def normal_claim_allowed(self, db, binding):
        """Only the validated selected queued job may be the claim transition."""
        try:
            self._transaction(db)
            row = VerificationQueue._record(db.execute(
                'SELECT * FROM verification_queue WHERE job_id=?', (binding.job_id,)).fetchone())
            _need(row is not None and row['state'] == 'queued'
                  and all(row[key] == value for key, value in binding.payload().items()),
                  'RECOVERY_NORMAL_CLAIM_CHANGED')
            VerificationQueue._run(db, binding, states={'QA_REQUIRED'})
            if self._recovery_available(db):
                _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?',
                                 (binding.job_id,)).fetchone() is None
                      and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?',
                                     (binding.job_id,)).fetchone() is None, 'RECOVERY_NORMAL_CLAIM_REPLAY_FORBIDDEN')
            for job_id in self._job_ids(db):
                if job_id == binding.job_id or not self._eligibility(db, job_id)['blocks_admission']:
                    continue
                # Waiting normal verifications are not live producers. They
                # still block admission/retry, but must not deadlock FIFO drain.
                waiting = VerificationQueue._record(db.execute(
                    'SELECT * FROM verification_queue WHERE job_id=?', (job_id,)).fetchone())
                _need(waiting is not None and waiting['state'] == 'queued'
                      and waiting['verifier_release_sha256'] == binding.verifier_release_sha256,
                      'RECOVERY_OTHER_ATTEMPT_UNRESOLVED')
                waiting_binding = VerificationBinding.from_payload({
                    key: waiting[key] for key in binding.payload()})
                VerificationQueue._run(db, waiting_binding, states={'QA_REQUIRED'})
                if self._recovery_available(db):
                    _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?',
                                     (job_id,)).fetchone() is None
                          and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?',
                                         (job_id,)).fetchone() is None, 'RECOVERY_OTHER_ATTEMPT_UNRESOLVED')
            return True
        except Exception:
            return False

    def rollout_readiness(self):
        """Read-only next-release guard: no schema creation, claim, or mutation."""
        try:
            with self._db() as db:
                db.execute('BEGIN')
                ready = self._other_work_allows(db)
                return {'ready': ready, 'state': 'NO_ACTIVE_WORK' if ready else 'UNRESOLVED_OR_ACTIVE_WORK',
                        'technical_verification_passed': False, 'human_acceptance_recorded': False}
        except Exception:
            return {'ready': False, 'state': 'UNAVAILABLE', 'technical_verification_passed': False,
                    'human_acceptance_recorded': False}

    def read_closed_state(self, disposition_sha256, job_id):
        """One coherent, read-only acknowledgement and old/new-store snapshot."""
        _need(_sha(disposition_sha256) and type(job_id) is str
              and re.fullmatch(r'fox-[a-f0-9]{20}', job_id), 'RECOVERY_READ_BINDING_INVALID')
        with self._db() as db:
            db.execute('BEGIN')
            closed, document = self._closed(db, job_id) if self._recovery_available(db) else (None, None)
            acknowledgement = None
            if closed is not None:
                _need(closed.disposition_sha256 == disposition_sha256, 'RECOVERY_READ_DISPOSITION_CHANGED')
                acknowledgement = {'status': 'FAILED_QA_RECORDED',
                    'disposition_sha256': closed.disposition_sha256, 'disposition': document}
            return {'acknowledgement': acknowledgement, 'eligibility': self._eligibility(db, job_id),
                    'union_ready': self._other_work_allows(db)}

    def eligibility(self, job_id):
        try:
            with self._db() as db:
                return self._eligibility(db, job_id)
        except Exception:
            return {'blocks_admission': True, 'recovery_state': 'unavailable', 'retry_eligible': False}

    def reserve_retry(self, request_raw, *, now=None):
        request = validate_retry_request(_load(request_raw, 16_384))
        _need(request_raw == canonical_bytes(request), 'RECOVERY_EXACT_RETRY_REQUEST_REQUIRED')
        request_sha = digest(request_raw)
        with self._db(True) as db:
            existing = db.execute('SELECT attempt_id,request_raw FROM verification_retry_attempts WHERE request_id=?',
                                  (request['request_id'],)).fetchone()
            if existing is not None:
                _need(existing['request_raw'] == request_raw, 'RECOVERY_RETRY_REQUEST_REBOUND')
                closed, _ = self._closed(db, request['binding']['job_id'])
                _need(closed is not None and closed.disposition_sha256 == request['disposition_sha256'],
                      'RECOVERY_CLOSED_FAILURE_CHANGED')
                return {'status': 'RETRY_RESERVED', 'request_sha256': request_sha,
                        'attempt': self._attempt(db, existing['attempt_id']), 'idempotent': True}
            binding = VerificationBinding.from_payload(request['binding'])
            closed, document = self._closed(db, binding.job_id)
            _need(closed is not None and closed.disposition_sha256 == request['disposition_sha256']
                  and binding.verifier_release_sha256 in self.approved_retry_releases
                  and binding.verifier_release_sha256 != closed.binding.verifier_release_sha256
                  and all(getattr(binding, key) == getattr(closed.binding, key)
                          for key in ('job_id', 'source_manifest_sha256', 'package_sha256')),
                  'RECOVERY_RETRY_NOT_AUTHORIZED')
            self._server_run(db, binding, unverified=True)
            _need(self._other_work_allows(db), 'RECOVERY_ACTIVE_WORK_BLOCKS_RETRY')
            v2 = document['producer'].get('scope') == SYNCHRONOUS_INVENTORY_SCOPE
            if not v2:
                self._observe(document, _clock(now))
            self._insert(db, 'verification_retry_attempts', {'attempt_id': request['attempt_id'],
                'request_id': request['request_id'], 'disposition_sha256': request['disposition_sha256'],
                'job_id': binding.job_id, 'request_raw': request_raw, 'request_sha256': request_sha,
                'created_at_utc': _clock(now).isoformat()})
            self._event(db, request['attempt_id'], 'reserved', {'request_sha256': request_sha}, now)
            if v2:
                _need(binding.verifier_release_sha256 == self.current_verifier_release_sha256,
                      'RECOVERY_CURRENT_RELEASE_CHANGED')
                self._append_observation(db, document, purpose='retry_reservation',
                                          attempt_id=request['attempt_id'], now=now)
            attempt = self._attempt(db, request['attempt_id'])
        return {'status': 'RETRY_RESERVED', 'request_sha256': request_sha, 'attempt': attempt, 'idempotent': False}

    def get_attempt(self, attempt_id):
        _need(type(attempt_id) is str and _ATTEMPT.fullmatch(attempt_id), 'RECOVERY_ATTEMPT_ID_INVALID')
        with self._db() as db:
            return self._attempt(db, attempt_id)

    def claim_retry(self, attempt_id):
        with self._db(True) as db:
            current = self._attempt(db, attempt_id, private=True)
            _need(current is not None and current['state'] == 'reserved', 'RECOVERY_RETRY_ALREADY_CLAIMED_OR_UNAVAILABLE')
            binding = VerificationBinding.from_payload(current['binding'])
            closed, _ = self._closed(db, binding.job_id)
            _need(closed is not None and closed.disposition_sha256 == current['disposition_sha256'],
                  'RECOVERY_CLOSED_FAILURE_CHANGED')
            self._server_run(db, binding, unverified=True)
            _need(self._other_work_allows(db, except_job_id=binding.job_id), 'RECOVERY_ACTIVE_WORK_BLOCKS_RETRY')
            token = secrets.token_hex(16)
            self._event(db, attempt_id, 'running', {'attempt_token': token}, None, current)
            return RetryClaim(attempt_id, binding, token)

    def _claim(self, db, claim):
        _need(type(claim) is RetryClaim, 'RECOVERY_RETRY_CLAIM_REQUIRED')
        current = self._attempt(db, claim.attempt_id, private=True)
        _need(current is not None and current['binding'] == claim.binding.payload()
              and current['attempt_token'] == claim.attempt_token, 'RECOVERY_RETRY_CLAIM_CHANGED')
        return current

    def mark_retry_attention(self, claim):
        with self._db(True) as db:
            current = self._claim(db, claim)
            _need(current['state'] in {'running', 'attention'}, 'RECOVERY_RETRY_STATE_CHANGED')
            if current['state'] == 'running':
                self._event(db, claim.attempt_id, 'attention', {'code': 'OUTCOME_UNCONFIRMED'}, None, current)
            return self._attempt(db, claim.attempt_id)

    def complete_retry(self, claim, result):
        """Record only an independently retained technical proof; never promote."""
        with self._db(True) as db:
            current = self._claim(db, claim)
            _need(current['state'] in {'running', 'attention', 'completed'}, 'RECOVERY_RETRY_STATE_CHANGED')
            queue = VerificationQueue(self.database, enabled=True, verifier_release_sha256=claim.binding.verifier_release_sha256)
            queue._validated_proof(db, claim.binding, result)
            if current['state'] == 'completed':
                _need(current['proof_sha256'] == result.proof_sha256, 'RECOVERY_COMPLETION_REBOUND')
            else:
                self._event(db, claim.attempt_id, 'completed', {'proof_sha256': result.proof_sha256}, None, current)
            return self._attempt(db, claim.attempt_id)

    def reconcile_retry_completed(self, request_sha256, attempt_id, binding, *, now=None):
        """Protected proof-only reconciliation; never claim or replay a phase."""
        _need(_sha(request_sha256) and type(binding) is VerificationBinding,
              'RECOVERY_RECONCILE_BINDING_REQUIRED')
        with self._db(True) as db:
            current = self._attempt(db, attempt_id, private=True)
            _need(current is not None and current['request_sha256'] == request_sha256
                  and current['binding'] == binding.payload()
                  and current['state'] in {'running', 'attention', 'completed'}
                  and type(current['attempt_token']) is str,
                  'RECOVERY_RECONCILE_ATTEMPT_CHANGED')
            closed, _ = self._closed(db, binding.job_id)
            _need(closed is not None and closed.disposition_sha256 == current['disposition_sha256'],
                  'RECOVERY_CLOSED_FAILURE_CHANGED')
            stored = db.execute('SELECT proof_sha256 FROM technical_verifications WHERE run=?',
                                (binding.job_id,)).fetchone()
            _need(stored is not None and _sha(stored['proof_sha256']),
                  'RECOVERY_RECONCILE_PROOF_REQUIRED')
            proof = TechnicalProofResult(stored['proof_sha256'])
            queue = VerificationQueue(self.database, enabled=True,
                                      verifier_release_sha256=binding.verifier_release_sha256)
            queue._validated_proof(db, binding, proof)
            if current['state'] == 'completed':
                _need(current['proof_sha256'] == proof.proof_sha256, 'RECOVERY_COMPLETION_REBOUND')
            else:
                self._event(db, attempt_id, 'completed', {'proof_sha256': proof.proof_sha256}, now, current)
            return self._attempt(db, attempt_id)
