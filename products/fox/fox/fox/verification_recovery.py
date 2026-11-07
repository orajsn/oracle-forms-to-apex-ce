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


def terminal_empty_prototype_mapping(database, db, run, *, claim_owner_failure=False):
    """Recognize one sealed first EMPTY mapper, not success or retry authority.

    Deliberately self-contained stdlib: the transition bridge also loads this
    reviewed module in the serving legacy namespace, which has no new prototype
    modules. Producer-held durable bindings are checked here; fresh XML semantic
    reconstruction and current processing consent remain the recovery API's job.
    Unknown/missing/extra evidence and all later work remain blocking.
    """
    import math
    import os

    def need(value):
        if not value:
            raise ValueError('Unconfirmed terminal prototype mapping.')

    def sha(value):
        return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')

    def hashed(value):
        return hashlib.sha256(canonical(value)).hexdigest()

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def protected(path, private=False):
        need(not path.is_symlink())
        if os.name == 'posix':
            metadata = path.stat()
            need(metadata.st_uid == owner_uid and metadata.st_mode & (0o077 if private else 0o022) == 0)

    def read(path, maximum=2_000_000):
        protected(path)
        need(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= maximum)
        need(path.stat().st_nlink == 1)
        raw = path.read_bytes()
        need(0 < len(raw) <= maximum)
        observed[path.relative_to(job).as_posix()] = raw
        return raw

    def document(path, maximum=2_000_000):
        value = json.loads(read(path, maximum).decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda _: need(False))
        need(type(value) is dict)
        canonical(value)  # Also refuse overflowing/nonfinite decoded numbers.
        return value

    def same(left, right):
        need(canonical(left) == canonical(right))

    def timestamp(value):
        need(type(value) is str and re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value))
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

    try:
        need(type(run) is dict and run.get('state') == 'ATTENTION' and run.get('artifact') is None
             and type(run.get('id')) is str and re.fullmatch(r'fox-[a-f0-9]{20}', run['id'])
             and sha(run.get('source_hash')) and type(run.get('project')) is str)
        root = Path(database).absolute().parent
        job = root / 'jobs' / run['id']
        need(root.resolve() == root and all(not path.is_symlink() and path.is_dir()
             for path in (root, root / 'jobs', job)))
        owner_uid = root.stat().st_uid if os.name == 'posix' else None
        # The stopped transition reader is rootless-namespace UID0 reading the
        # fixed existing UID1000 data. Live FOX reads as UID1000. Ownership must
        # remain consistent; this grants no write/execution or path authority.
        if os.name == 'posix':
            need(os.geteuid() == owner_uid or os.geteuid() == 0 and owner_uid == 1000)
        protected(root, private=True)
        protected(Path(database).absolute())
        need(Path(database).absolute().stat().st_nlink == 1)
        protected(root / 'jobs')
        protected(job)
        observed = {}
        snapshot = document(job / 'source-snapshot.json', 20_000_000)
        snapshot_keys = {'project', 'project_id', 'project_name', 'source_hash', 'conversion_profile',
                         'selected_source_set_id', 'files', 'prototype', 'approvals'}
        if claim_owner_failure and 'retry_of' in snapshot:
            snapshot_keys.update(('retry_of', 'mapping_recovery'))
            parent, metadata = snapshot['retry_of'], snapshot['mapping_recovery']
            need(type(parent) is str and re.fullmatch(r'fox-[a-f0-9]{20}', parent)
                 and run['id'] == 'fox-' + hashed({'parent_run_id': parent, 'strategy': 'repartition-32-v1'})[:20]
                 and type(metadata) is dict and set(metadata) == {'schema_version', 'strategy', 'parent_snapshot_sha256'}
                 and type(metadata['schema_version']) is int and metadata['schema_version'] == 1
                 and metadata['strategy'] == 'repartition-32-v1' and sha(metadata['parent_snapshot_sha256']))
        need(type(claim_owner_failure) is bool and set(snapshot) == snapshot_keys
             and snapshot['conversion_profile'] == 'native-blueprint-prototype-v1'
             and snapshot['project'] == snapshot['project_id'] == run['project']
             and snapshot['source_hash'] == run['source_hash']
             and type(snapshot['project_name']) is str and 1 <= len(snapshot['project_name']) <= 120
             and type(snapshot['selected_source_set_id']) is str
             and re.fullmatch(r'ss-[a-f0-9]{32}', snapshot['selected_source_set_id']))
        owner = db.execute('SELECT owner FROM projects WHERE id=?', (run['project'],)).fetchone()
        approvals, selected = snapshot['approvals'], snapshot['prototype']
        need(owner is not None and type(owner[0]) is str
             and type(approvals) is dict and set(approvals) ==
                 {'redacted_source', 'external_ai', 'synthetic_prototype', 'owner', 'approved_at'}
             and approvals['owner'] == owner[0] and 1 <= len(owner[0]) <= 180
             and all(approvals[key] is True for key in ('redacted_source', 'external_ai', 'synthetic_prototype'))
             and type(approvals['approved_at']) in (int, float)
             and math.isfinite(approvals['approved_at']) and approvals['approved_at'] > 0
             and type(selected) is dict and type(selected.get('schema_version')) is int)
        version = selected['schema_version']
        keys = {'schema_version', 'source_binding', 'focus_plan_sha256', 'approved_chunk_hashes',
                'approved_policy_id', 'target_profile_sha256'}
        if version == 2:
            keys.add('max_owned_objects')
        need(set(selected) == keys and version in (1, 2)
             and (version == 1 or type(selected['max_owned_objects']) is int and selected['max_owned_objects'] == 32)
             and all(sha(selected[key]) for key in ('source_binding', 'focus_plan_sha256', 'target_profile_sha256'))
             and selected['approved_policy_id'] == 'fox-demo-synthetic-schema-v1'
             and type(selected['approved_chunk_hashes']) is dict and len(selected['approved_chunk_hashes']) <= 4096
             and all(type(key) is str and sha(value) for key, value in selected['approved_chunk_hashes'].items()))
        origin = 'approved_prototype_mapping_retry' if 'retry_of' in snapshot else 'approved_prototype_conversion'
        events = db.execute('SELECT owner,created FROM events WHERE action=? AND object_id=?', (origin, run['id'])).fetchall()
        need(len(events) == 1 and events[0][0] == owner[0] and events[0][1] == approvals['approved_at'])
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, column in (('verification_queue', 'job_id'), ('verification_failed_dispositions', 'job_id'),
                ('verification_retry_attempts', 'job_id'), ('verification_precheck_failures', 'job_id'),
                ('verification_qa_stage_failures', 'job_id'), ('verification_project_prewrite_failures', 'job_id'),
                ('technical_verifications', 'run'), ('acceptances', 'run')):
            if table in tables:
                need(db.execute('SELECT 1 FROM ' + table + ' WHERE ' + column + '=? LIMIT 1', (run['id'],)).fetchone() is None)
        head = db.execute('SELECT project,source_hash,file_count,source_bytes FROM source_sets WHERE id=?',
                          (snapshot['selected_source_set_id'],)).fetchone()
        files = snapshot['files']
        # Historical no-execution classification uses the retained version,
        # not today's selected pointer. Fresh retry permission checks both.
        need(head is not None and head[0] == run['project'] and head[1] == run['source_hash']
             and type(files) is list and 1 <= len(files) <= 4 and head[2] == len(files))
        rows = db.execute('SELECT s.id,s.project,s.name,s.sha256,s.bytes,s.text,s.created '
            'FROM source_set_members m JOIN sources s ON s.id=m.source_id '
            'WHERE m.source_set_id=? AND m.name=s.name AND m.sha256=s.sha256 AND m.bytes=s.bytes '
            'ORDER BY m.name', (snapshot['selected_source_set_id'],)).fetchall()
        same([dict(zip(('id', 'project', 'name', 'sha256', 'bytes', 'text', 'created'), row)) for row in rows], files)
        originals = []
        for source in files:
            need(type(source['name']) is str and source['name'].lower().endswith('.xml')
                 and not any(char in source['name'] for char in '/\\:') and sha(source['sha256'])
                 and type(source['text']) is str and type(source['bytes']) is int
                 and 0 < source['bytes'] <= 5 * 1024 * 1024 and source['project'] == run['project'])
            raw = source['text'].encode('utf-8')
            if hashlib.sha256(raw).hexdigest() != source['sha256']:
                raw = b'\xef\xbb\xbf' + raw
            need(len(raw) == source['bytes'] and hashlib.sha256(raw).hexdigest() == source['sha256'])
            originals.append(raw)
        need(len({row['name'].casefold() for row in files}) == len(files)
             and head[3] == sum(len(raw) for raw in originals)
             and hashlib.sha256('\n'.join(row['name'] + ':' + row['sha256'] for row in files).encode()).hexdigest() == run['source_hash'])
        pipeline = job / 'prototype-pipeline'
        need(not pipeline.is_symlink() and pipeline.is_dir()
             and not (pipeline / 'sources').is_symlink() and (pipeline / 'sources').is_dir())
        protected(pipeline)
        protected(pipeline / 'sources')
        binding = document(pipeline / 'binding.json')
        manifest = document(pipeline / 'sources-manifest.json')
        same(manifest, {'source_binding': selected['source_binding'], 'selected_chunk_hashes': selected['approved_chunk_hashes'],
            'files': [{'name': row['name'], 'sha256': row['sha256'], 'bytes': row['bytes']} for row in files]})
        packet = document(pipeline / 'packet.json', 20_000_000)
        need(packet['schema_version'] == 1 and type(packet['schema_version']) is int
             and packet['scope'] == 'fox-forms-understanding-packet-v1'
             and packet['selection_status'] == 'NOT_SELECTED' and packet['transfer_authorized'] is False
             and packet['caller_must_check_processing_approval'] is True
             and packet['safety'] == {'code_executed': False, 'source_content_is_untrusted': True,
                 'model_submission_allowed': False, 'native_generation_allowed': False}
             and hashed({'sources': packet['sources'], 'chunks': packet['chunks']}) == packet['source_binding'] == selected['source_binding']
             and len(packet['sources']) == len(files))
        all_objects, first_group = {}, []
        source_index = []
        for index, (entry, source) in enumerate(zip(packet['sources'], files)):
            descriptor = {'name': source['name'], 'sha256': source['sha256'], 'bytes': source['bytes'], 'encoding': 'utf-8'}
            same(entry['source'], descriptor)
            same(entry['facts']['source'], descriptor)
            source_index.append(descriptor)
            for obj in entry['facts']['objects']:
                need(type(obj['id']) is str and obj['id'] not in all_objects)
                all_objects[obj['id']] = obj
            if index == 0:
                objects = entry['facts']['objects']
                need(type(objects) is list and len(objects) > 0)
                first = objects[0]
                group = (first['block_id'] or (first['id'] if first['kind'] == 'Block' else None), first['module_id'])
                first_group = [obj for obj in objects if
                    (obj['block_id'] or (obj['id'] if obj['kind'] == 'Block' else None), obj['module_id']) == group]
            need(read(pipeline / 'sources' / ('source-%03d.xml' % index), 5 * 1024 * 1024) == originals[index])
        chunks = {row['id']: row for row in packet['chunks']}
        need(len(chunks) == len(packet['chunks']) and all(key in chunks and chunks[key]['sha256'] == value
             for key, value in selected['approved_chunk_hashes'].items()))
        focuses = [path for path in pipeline.iterdir() if path.name.startswith('focus-')]
        if claim_owner_failure:
            need(1 <= len(focuses) <= 256)
            ordered = []
            for entry in packet['sources']:
                groups = {}
                for obj in entry['facts']['objects']:
                    key = ('block', obj['block_id'] or obj['id']) if obj['block_id'] or obj['kind'] == 'Block' else ('globals', obj['module_id'])
                    groups.setdefault(key, []).append(obj)
                ordered.extend(obj for group in groups.values() for obj in group)
            requests = []
            for directory in focuses:
                need(not directory.is_symlink() and directory.is_dir())
                protected(directory)
                requests.append((document(directory / 'request.json'), directory))
            positions = {obj['id']: index for index, obj in enumerate(ordered)}
            requests.sort(key=lambda pair: positions[pair[0]['owned_objects'][0]['id']])
            target = document(requests[0][1] / 'mapper-target.json')
            roles = target['opaf']['roles']
            need(hashed(target) == selected['target_profile_sha256'] and target['active'] is True
                 and target['scope']['data_mode'] == 'synthetic_test_only'
                 and target['scope']['existing_resources_only'] is True
                 and target['scope']['customer_deployment_authorized'] is False
                 and set(roles) == {'mapper', 'reviewer'}
                 and roles['mapper']['workflow_id'].upper() != roles['reviewer']['workflow_id'].upper())
            expected_binding = {'schema_version': version, 'job_id': run['id'], 'project_id': run['project'],
                'project_name': snapshot['project_name'], 'source_binding': selected['source_binding'],
                'focus_plan_sha256': selected['focus_plan_sha256'], 'profile_sha256': hashed(roles),
                'approved_policy_id': selected['approved_policy_id']}
            if version == 2:
                expected_binding['max_owned_objects'] = 32
            same(binding, expected_binding)

            def role_output(directory, name, payload):
                same(document(directory / (name + '-target.json')), target)
                saved = document(directory / (name + '.json'))
                need(set(saved) == {'binding', 'output', 'output_sha256', 'invocation', 'model_environment', 'model_environment_sha256'})
                role = roles[name]
                need(set(role) == {'workflow_id', 'model', 'graph_sha256'} and sha(role['graph_sha256'])
                     and type(role['workflow_id']) is str and re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                     and type(role['model']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', role['model']))
                role_binding = {'role': role, 'request_sha256': hashed(payload),
                                'job_id': run['id'], 'source_hash': selected['source_binding']}
                same(saved['binding'], role_binding)
                same(document(directory / (name + '-intent.json')), role_binding)
                need(hashed(saved['output']) == saved['output_sha256'])
                invocation, environment = saved['invocation'], saved['model_environment']
                need(set(invocation) == {'workflow_id', 'room_id', 'model', 'graph_sha256', 'request_sha256',
                     'response_sha256', 'started_at_utc', 'completed_at_utc'}
                     and invocation['request_sha256'] == hashed(payload) and sha(invocation['response_sha256'])
                     and type(invocation['room_id']) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', invocation['room_id'])
                     and all(invocation[key] == role[key] for key in ('workflow_id', 'model', 'graph_sha256'))
                     and hashed(environment) == saved['model_environment_sha256'])
                same(environment, {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
                    'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation', 'job_id': run['id'],
                    'role': name, 'source_manifest_sha256': selected['source_binding'],
                    'target_profile_sha256': selected['target_profile_sha256'], 'observed_at_utc': environment['observed_at_utc'],
                    'opaf': {key: target['opaf'][key] for key in ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                    'workflow': {**role, 'published': True}, 'opaf_version': target['tested_versions']['opaf']})
                started, finished, at = (timestamp(value) for value in
                    (invocation['started_at_utc'], invocation['completed_at_utc'], environment['observed_at_utc']))
                need(finished >= started and -5 <= started - at <= 120)
                return saved['output'], invocation['room_id']

            def identifier(value):
                need(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}', value))

            def text(value, maximum=2000):
                need(type(value) is str and value.strip() and len(value) <= maximum
                     and not any(ord(char) < 32 and char not in '\n\r\t' for char in value))

            def shape(candidate, request, owned_ids):
                need(type(candidate) is dict and set(candidate) == {'focus_id', 'focus_binding', 'blueprint'}
                     and candidate['focus_id'] == request['focus_id'] and candidate['focus_binding'] == request['focus_binding'])
                blueprint = candidate['blueprint']
                arrays = ('objects', 'screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions')
                need(type(blueprint) is dict and set(blueprint) == {'schema_version', 'scope', 'source_binding', *arrays}
                     and type(blueprint['schema_version']) is int and blueprint['schema_version'] == 1
                     and blueprint['scope'] == 'fox-forms-blueprint-v1' and blueprint['source_binding'] == selected['source_binding']
                     and all(type(blueprint[name]) is list and len(blueprint[name]) <= 10000 for name in arrays)
                     and len(canonical(candidate)) <= 500000)
                seen = set()
                for row in blueprint['objects']:
                    need(type(row) is dict and {'source_object_id', 'disposition', 'reason'} <= row.keys()
                         and not row.keys() - {'source_object_id', 'disposition', 'reason', 'screen_id', 'native_component'}
                         and row['source_object_id'] in owned_ids and row['source_object_id'] not in seen
                         and row['disposition'] in ('proposed', 'omitted', 'unresolved'))
                    seen.add(row['source_object_id']); text(row['reason'])
                    if 'screen_id' in row: identifier(row['screen_id'])
                    if 'native_component' in row: need(row['native_component'] in ('form', 'interactive-grid', 'report', 'page-items'))
                need(seen == owned_ids)
                for row in blueprint['screens']:
                    need(set(row) == {'id', 'title'}); identifier(row['id']); text(row['title'], 300)
                for row in blueprint['claims']:
                    need(set(row) == {'id', 'source_object_id', 'kind', 'value', 'status', 'evidence_refs', 'reason'}
                         and row['source_object_id'] in owned_ids and row['status'] in ('source_fact', 'proposal', 'unresolved')
                         and type(row['evidence_refs']) is list and len(row['evidence_refs']) <= 10000)
                    identifier(row['id']); text(row['kind'], 100); text(row['reason'])
                    values = row['value'] if type(row['value']) is list else [row['value']]
                    need(len(values) <= 32)
                    for value in values:
                        if type(value) is str: text(value, 512)
                        else: need(value is None or type(value) in (bool, int))
                    for value in row['evidence_refs']: identifier(value)
                for category in ('relationships', 'actions'):
                    for row in blueprint[category]:
                        need(set(row) == {'id', 'claim_ids'} and type(row['claim_ids']) is list)
                        identifier(row['id'])
                        for value in row['claim_ids']: identifier(value)
                for row in blueprint['questions']:
                    need(set(row) == {'id', 'source_object_id', 'text'} and row['source_object_id'] in owned_ids)
                    identifier(row['id']); text(row['text'])
                for row in blueprint['assumptions']:
                    need(set(row) == {'id', 'text', 'scope'} and row['scope'] == 'prototype-only')
                    identifier(row['id']); text(row['text'])

            cursor, failure, rooms = 0, False, set()
            unit_metadata = {unit['id']: unit for entry in packet['sources'] for unit in entry['facts']['code_units']}
            for number, (request, directory) in enumerate(requests):
                need(not failure and type(request['schema_version']) is int and request['schema_version'] == 1
                     and request['scope'] == 'fox-forms-focus-request-v1' and request['source_binding'] == selected['source_binding']
                     and hashed({key: value for key, value in request.items() if key != 'focus_binding'}) == request['focus_binding']
                     and type(request['owned_objects']) is list and 0 < len(request['owned_objects']) <= (250 if version == 1 else 32))
                owned = request['owned_objects']; owned_ids = {row['id'] for row in owned}
                same(owned, ordered[cursor:cursor + len(owned)]); cursor += len(owned)
                need(request['focus_id'] == directory.name == 'focus-' + hashed([selected['source_binding'], [row['id'] for row in owned]])[:24])
                same(request['source_index'], source_index)
                same(request['safety'], {'source_content_is_untrusted': True, 'code_executed': False,
                    'transfer_authorized': False, 'caller_must_check_processing_approval': True, 'native_generation_allowed': False})
                for row in request['context_objects']: same(row, all_objects[row['id']])
                for unit in request['code_units']: same(unit, unit_metadata[unit['id']])
                for chunk in request['chunks']:
                    same({key: value for key, value in chunk.items() if key != 'text'}, chunks[chunk['id']])
                    need(selected['approved_chunk_hashes'].get(chunk['id']) == chunk['sha256']
                         and len(chunk['text'].encode()) == chunk['bytes'] and hashlib.sha256(chunk['text'].encode()).hexdigest() == chunk['sha256'])
                candidate, mapper_room = role_output(directory, 'mapper', request)
                need(mapper_room not in rooms); rooms.add(mapper_room)
                if (directory / 'reviewer.json').exists():
                    shape(candidate, request, owned_ids)
                    review, room = role_output(directory, 'reviewer', {'request': request,
                        'candidate': candidate, 'candidate_sha256': hashed(candidate)})
                    need(room not in rooms); rooms.add(room)
                    same(review, {'source_binding': selected['source_binding'], 'focus_binding': request['focus_binding'],
                        'candidate_sha256': hashed(candidate), 'verdict': 'APPROVED', 'findings': []})
                    same(document(directory / 'review-receipt.json'), {'verdict': 'APPROVED',
                        'candidate_sha256': hashed(candidate), 'source_binding': selected['source_binding'],
                        'focus_binding': request['focus_binding'], 'approved_structured_design': True,
                        **{key: False for key in ('generation_ready', 'native_apex_generated', 'native_apex_validity_verified', 'import_verified', 'business_behavior_accepted')}})
                else:
                    need(number == len(requests) - 1)
                    unit_ids = [unit['id'] for unit in request['code_units']]
                    object_ids = [row['id'] for row in request['owned_objects'] + request['context_objects']]
                    need(len(set(unit_ids)) == len(unit_ids) and len(set(object_ids)) == len(object_ids) and not set(unit_ids) & set(object_ids))
                    units = {unit['id']: unit for unit in request['code_units']}
                    normalized = json.loads(canonical(candidate)); changes = 0
                    for claim in normalized['blueprint']['claims']:
                        ref = claim['source_object_id']
                        if ref in owned_ids: continue
                        unit = units[ref]; refs = claim['evidence_refs']
                        need(unit['owner_id'] in owned_ids and type(refs) is list and ref in refs and len(set(refs)) == len(refs)
                             and all(value == unit['owner_id'] or value in units and units[value]['owner_id'] == unit['owner_id'] for value in refs))
                        claim['source_object_id'] = unit['owner_id']; changes += 1
                    need(changes > 0); shape(normalized, request, owned_ids); failure = True
            need(failure)
            assessment = document(pipeline / 'assessment.json')
            need(set(assessment) == {'source_binding', 'source_count', 'source_objects', 'focus_count'}
                 and assessment['source_binding'] == selected['source_binding'] and assessment['source_count'] == len(files)
                 and assessment['source_objects'] == len(all_objects) and type(assessment['focus_count']) is int
                 and len(requests) <= assessment['focus_count'] <= 256)
            allowed = set(observed) | {'prototype-pipeline', 'prototype-pipeline/sources'} | {
                'prototype-pipeline/' + directory.name for _, directory in requests}
            pending, actual = [job], set()
            while pending:
                for path in pending.pop().iterdir():
                    name = path.relative_to(job).as_posix(); need(name in allowed and not path.is_symlink()); actual.add(name)
                    if path.is_dir(): pending.append(path)
                    else: need(path.is_file() and name in observed and path.read_bytes() == observed[name])
            need(actual == allowed)
            return True
        need(len(focuses) == 1 and not focuses[0].is_symlink() and focuses[0].is_dir())
        focus = focuses[0]
        protected(focus)
        request = document(focus / 'request.json')
        need(set(request) == {'schema_version', 'scope', 'source_binding', 'focus_id', 'focus_binding', 'source_index',
            'owned_objects', 'context_objects', 'code_units', 'links', 'dependencies', 'findings', 'chunks',
            'unselected_code_unit_ids', 'safety'} and type(request['schema_version']) is int and request['schema_version'] == 1
            and request['scope'] == 'fox-forms-focus-request-v1' and request['source_binding'] == selected['source_binding']
            and sha(request['focus_binding']) and hashed({key: value for key, value in request.items() if key != 'focus_binding'}) == request['focus_binding']
            and type(request['owned_objects']) is list and 0 < len(request['owned_objects']) <= (250 if version == 1 else 32))
        owned = request['owned_objects']
        same(owned, first_group[:len(owned)])
        need(request['focus_id'] == focus.name == 'focus-' + hashed([selected['source_binding'], [row['id'] for row in owned]])[:24])
        same(request['source_index'], source_index)
        same(request['safety'], {'source_content_is_untrusted': True, 'code_executed': False,
             'transfer_authorized': False, 'caller_must_check_processing_approval': True, 'native_generation_allowed': False})
        for row in request['context_objects']:
            same(row, all_objects[row['id']])
        for row in request['chunks']:
            text = row['text'].encode('utf-8')
            same({key: value for key, value in row.items() if key != 'text'}, chunks[row['id']])
            need(selected['approved_chunk_hashes'].get(row['id']) == row['sha256']
                 and len(text) == row['bytes'] and hashlib.sha256(text).hexdigest() == row['sha256'])
        assessment = document(pipeline / 'assessment.json')
        need(set(assessment) == {'source_binding', 'source_count', 'source_objects', 'focus_count'}
             and assessment['source_binding'] == selected['source_binding'] and assessment['source_count'] == len(files)
             and assessment['source_objects'] == len(all_objects) and type(assessment['focus_count']) is int
             and 1 <= assessment['focus_count'] <= 256)
        target = document(focus / 'mapper-target.json')
        need(hashed(target) == selected['target_profile_sha256'] and target['active'] is True
             and target['scope']['data_mode'] == 'synthetic_test_only' and target['scope']['existing_resources_only'] is True
             and target['scope']['customer_deployment_authorized'] is False)
        roles = target['opaf']['roles']
        need(type(roles) is dict and set(roles) == {'mapper', 'reviewer'})
        for role in roles.values():
            need(type(role) is dict and set(role) == {'workflow_id', 'model', 'graph_sha256'}
                 and type(role['workflow_id']) is str and re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                 and type(role['model']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', role['model']) and sha(role['graph_sha256']))
        need(roles['mapper']['workflow_id'].upper() != roles['reviewer']['workflow_id'].upper())
        expected_binding = {'schema_version': version, 'job_id': run['id'], 'project_id': run['project'],
            'project_name': snapshot['project_name'], 'source_binding': selected['source_binding'],
            'focus_plan_sha256': selected['focus_plan_sha256'], 'profile_sha256': hashed(roles),
            'approved_policy_id': selected['approved_policy_id']}
        if version == 2:
            expected_binding['max_owned_objects'] = 32
        same(binding, expected_binding)
        saved = document(focus / 'mapper.json')
        need(set(saved) == {'binding', 'output', 'output_sha256', 'invocation', 'model_environment', 'model_environment_sha256'})
        identity = {'job_id': run['id'], 'source_hash': selected['source_binding']}
        role_binding = {'role': roles['mapper'], 'request_sha256': hashed(request), **identity}
        same(saved['binding'], role_binding)
        same(document(focus / 'mapper-intent.json'), role_binding)
        output = saved['output']
        need(type(output) is dict and set(output) == {'focus_id', 'focus_binding', 'blueprint'}
             and output['focus_id'] == request['focus_id'] and output['focus_binding'] == request['focus_binding']
             and hashed(output) == saved['output_sha256'])
        same(output['blueprint'], {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
            'source_binding': selected['source_binding'], **{key: [] for key in
                ('objects', 'screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions')}})
        invocation, environment = saved['invocation'], saved['model_environment']
        need(set(invocation) == {'workflow_id', 'room_id', 'model', 'graph_sha256', 'request_sha256',
            'response_sha256', 'started_at_utc', 'completed_at_utc'}
            and invocation['request_sha256'] == hashed(request) and sha(invocation['response_sha256'])
            and type(invocation['room_id']) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', invocation['room_id'])
            and all(invocation[key] == roles['mapper'][key] for key in ('workflow_id', 'model', 'graph_sha256'))
            and hashed(environment) == saved['model_environment_sha256'])
        same(environment, {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
            'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
            'job_id': run['id'], 'role': 'mapper', 'source_manifest_sha256': selected['source_binding'],
            'target_profile_sha256': selected['target_profile_sha256'], 'observed_at_utc': environment['observed_at_utc'],
            'opaf': {key: target['opaf'][key] for key in ('base_url', 'certificate_sha256',
                'model_authentication', 'version_number', 'build_id')},
            'workflow': {**roles['mapper'], 'published': True}, 'opaf_version': target['tested_versions']['opaf']})
        started, completed, observed_at = (timestamp(value) for value in
            (invocation['started_at_utc'], invocation['completed_at_utc'], environment['observed_at_utc']))
        need(completed >= started and -5 <= started - observed_at <= 120)
        allowed = set(observed) | {'prototype-pipeline', 'prototype-pipeline/sources',
                                  'prototype-pipeline/' + focus.name}
        pending, actual = [job], set()
        while pending:
            for path in pending.pop().iterdir():
                name = path.relative_to(job).as_posix()
                need(name in allowed and not path.is_symlink())
                actual.add(name)
                if path.is_dir():
                    pending.append(path)
                else:
                    need(path.is_file() and name in observed and path.read_bytes() == observed[name])
        need(actual == allowed)
        return True
    except Exception:
        return False


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

    # A precheck failed before a QA producer existed. It must never be forged
    # into the completed-QA receipt family above. This separate append-only
    # ledger retains the original queue/run/claim unchanged and grants no retry.
    _PRECHECK_TABLE = 'verification_precheck_failures'
    _PRECHECK_COLUMNS = ('job_id', 'assessment_sha256', 'assessment_raw',
        'legacy_record_sha256', 'closed_at_utc', 'record_sha256')

    @classmethod
    def _precheck_definitions(cls):
        table = cls._PRECHECK_TABLE
        result = {('table', table): 'CREATE TABLE IF NOT EXISTS ' + table + '''(
            job_id TEXT PRIMARY KEY REFERENCES verification_queue(job_id),
            assessment_sha256 TEXT NOT NULL UNIQUE,assessment_raw BLOB NOT NULL,
            legacy_record_sha256 TEXT NOT NULL,closed_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)'''}
        for action in ('UPDATE', 'DELETE'):
            name = table + '_no_' + action.lower()
            result[('trigger', name)] = ('CREATE TRIGGER IF NOT EXISTS ' + name + ' BEFORE ' +
                action + ' ON ' + table + " BEGIN SELECT RAISE(ABORT,'precheck history is append-only'); END")
        return result

    @classmethod
    def _precheck_schema(cls, db, *, create=False):
        expected = cls._precheck_definitions()
        rows = [tuple(row) for row in db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','trigger')")
            if row[2] == cls._PRECHECK_TABLE or (row[0], row[1]) in expected]
        if not rows:
            if not create:
                return False
            _need(db.in_transaction, 'PRECHECK_SCHEMA_TRANSACTION_REQUIRED')
            for sql in expected.values(): db.execute(sql)
            return cls._precheck_schema(db)
        actual = {(row[0], row[1]): row[3] for row in rows}
        _need(set(actual) == set(expected) and all(
            cls.normalized_schema_sql(actual[key]) == cls.normalized_schema_sql(sql)
            for key, sql in expected.items()), 'PRECHECK_SCHEMA_OR_FENCES_CHANGED')
        _need(tuple(row[1] for row in db.execute('PRAGMA table_info(' + cls._PRECHECK_TABLE + ')'))
              == cls._PRECHECK_COLUMNS, 'PRECHECK_SCHEMA_COLUMNS_CHANGED')
        return True

    def initialize_precheck_ledger(self, *, apply=False):
        _need(apply is True, 'PRECHECK_EXPLICIT_INITIALIZATION_REQUIRED')
        with self._db(True) as db:
            db.execute('SELECT job_id,record_sha256 FROM verification_queue LIMIT 0')
            existed = self._precheck_schema(db)
            self._precheck_schema(db, create=True)
            return {'status': 'PRECHECK_LEDGER_READY', 'created': not existed,
                    'technical_success': False, 'automatic_retry_permitted': False}

    @staticmethod
    def _precheck_assessment(value):
        fields = {'schema_version', 'scope', 'status', 'binding', 'session', 'legacy_record_sha256',
            'claim_sha256', 'retained_sha256', 'package_sha256', 'source_snapshot_sha256',
            'release_evidence_sha256', 'plan_sha256', 'operator_code_sha256', 'failed_phase',
            'missing_dependency', 'current_admission_blocks', 'closure_performed',
            'technical_success', 'human_acceptance_recorded', 'automatic_replay_permitted', 'scope_note'}
        _need(type(value) is dict and set(value) == fields, 'PRECHECK_ASSESSMENT_FIELDS')
        _need(type(value['schema_version']) is int and value['schema_version'] == 1
              and value['scope'] == 'fox-read-only-precheck-assessment-v1'
              and value['status'] == 'CLASSIFIED_PRECHECK_FAILURE_REQUIRES_PROTECTED_RECOVERY'
              and value['failed_phase'] == 'clean_check'
              and value['missing_dependency'] == 'fox.project_qa_plan'
              and value['current_admission_blocks'] is True
              and all(value[key] is False for key in ('closure_performed', 'technical_success',
                  'human_acceptance_recorded', 'automatic_replay_permitted')),
              'PRECHECK_ASSESSMENT_NOT_FAILURE')
        binding = VerificationBinding.from_payload(value['binding'])
        _need(type(value['session']) is str and _SESSION.fullmatch(value['session'])
              and all(_sha(value[key]) for key in ('legacy_record_sha256', 'claim_sha256',
                  'package_sha256', 'source_snapshot_sha256', 'release_evidence_sha256',
                  'plan_sha256', 'operator_code_sha256'))
              and value['package_sha256'] == binding.package_sha256, 'PRECHECK_ASSESSMENT_BINDING')
        retained = value['retained_sha256']
        _need(type(retained) is dict and len(retained) == 7
              and all(type(name) is str and _sha(raw) for name, raw in retained.items()),
              'PRECHECK_RETAINED_MANIFEST')
        labels = [name for name in retained if re.fullmatch(r'p[0-9]{4}-clean-check\.intent\.json', name)]
        _need(len(labels) == 1, 'PRECHECK_PHASE_MANIFEST')
        prefix = labels[0].split('-', 1)[0]
        _need(set(retained) == {'session.json', 'attention.json', *(prefix + '-' + name for name in
              ('claim.intent.json', 'claim.complete.json', 'prepare.intent.json',
               'prepare.complete.json', 'clean-check.intent.json'))}, 'PRECHECK_PHASE_MANIFEST')
        _need(value['scope_note'] == 'Retained evidence classification only. No host authority, closure, import, retry or readiness is granted.',
              'PRECHECK_ASSESSMENT_SCOPE_NOTE')
        return binding

    def _precheck_current(self, db, assessment):
        binding = self._precheck_assessment(assessment)
        legacy = VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?',
                                                       (binding.job_id,)).fetchone())
        _need(legacy is not None and legacy['state'] == 'attention' and legacy['proof_sha256'] is None
              and legacy['record_sha256'] == assessment['legacy_record_sha256']
              and all(legacy[key] == item for key, item in binding.payload().items())
              and claim_sha256(Claim(binding, legacy['claim_token'])) == assessment['claim_sha256'],
              'PRECHECK_ORIGINAL_QUEUE_CHANGED')
        self._server_run(db, binding, unverified=True)
        job = self.database.parent / 'jobs' / binding.job_id
        _need(digest((job / 'source-snapshot.json').read_bytes()) == assessment['source_snapshot_sha256']
              and digest((job / 'release-evidence.json').read_bytes()) == assessment['release_evidence_sha256'],
              'PRECHECK_RETAINED_JOB_CHANGED')
        return binding

    def _closed_precheck(self, db, job_id):
        if not self._precheck_schema(db):
            return None
        row = db.execute('SELECT * FROM ' + self._PRECHECK_TABLE + ' WHERE job_id=?', (job_id,)).fetchone()
        if row is None:
            return None
        value = dict(row)
        _need(set(value) == set(self._PRECHECK_COLUMNS) and type(value['assessment_raw']) is bytes
              and value['record_sha256'] == self._record_hash(value)
              and digest(value['assessment_raw']) == value['assessment_sha256'], 'PRECHECK_LEDGER_ROW_CHANGED')
        assessment = _load(value['assessment_raw'])
        self._precheck_assessment(assessment)
        _need(canonical_bytes(assessment) == value['assessment_raw']
              and assessment['binding']['job_id'] == value['job_id']
              and assessment['legacy_record_sha256'] == value['legacy_record_sha256'],
              'PRECHECK_LEDGER_DOCUMENT_CHANGED')
        _time(value['closed_at_utc'])
        self._precheck_current(db, assessment)
        return {'status': 'FAILED_PRECHECK_CLOSED', 'job_id': job_id,
                'assessment_sha256': value['assessment_sha256'], 'technical_success': False,
                'human_acceptance_recorded': False, 'automatic_retry_permitted': False}

    @staticmethod
    def _precheck_original_rows(db):
        # Checked inside the same reserved write transaction as the append.
        # Auth/session activity need not be frozen; these are the protected
        # product outcomes and original attempt records, never a full DR claim.
        present = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result = {}
        for table in ('runs', 'verification_queue', 'technical_verifications', 'acceptances', 'events'):
            if table not in present: continue
            rows = [[{'blob_sha256': digest(value)} if type(value) is bytes else value for value in row]
                    for row in db.execute('SELECT * FROM ' + table)]
            result[table] = digest(canonical_bytes(rows))
        return result

    def close_precheck_failure(self, assessment_raw, *, expected_sha256, observer=None, apply=False, now=None):
        """Append a failure only; the protected caller owns exclusion/observation.

        observer(binding, session) must freshly re-run the measured classifier
        against the actual stopped producer under the caller's held host lock.
        Browser JSON, cached files and boolean passed=True are not observers.
        This method cannot install that transport or grant its authority.
        """
        _need(apply is True and callable(observer), 'PRECHECK_PROTECTED_OBSERVER_REQUIRED')
        _need(type(assessment_raw) is bytes and len(assessment_raw) <= 65_536
              and _sha(expected_sha256) and digest(assessment_raw) == expected_sha256,
              'PRECHECK_EXACT_REVIEWED_ASSESSMENT_REQUIRED')
        assessment = _load(assessment_raw)
        binding = self._precheck_assessment(assessment)
        _need(canonical_bytes(assessment) == assessment_raw, 'PRECHECK_CANONICAL_ASSESSMENT_REQUIRED')
        with self._db(True) as db:
            _need(self._precheck_schema(db), 'PRECHECK_EXPLICIT_LEDGER_INITIALIZATION_REQUIRED')
            existing = self._closed_precheck(db, binding.job_id)
            if existing:
                _need(existing['assessment_sha256'] == expected_sha256, 'PRECHECK_DIFFERENT_CLOSURE_EXISTS')
                return {**existing, 'action': 'ALREADY_RECORDED_NO_REPLAY'}
            _need(self._closed_qa_stage(db,binding.job_id) is None and self._closed_project_prewrite(db,binding.job_id) is None,
                  'PRECHECK_CONFLICTING_RECOVERY_HISTORY')
            if self._recovery_available(db):
                _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?',
                                 (binding.job_id,)).fetchone() is None
                      and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?',
                                     (binding.job_id,)).fetchone() is None, 'PRECHECK_CONFLICTING_RECOVERY_HISTORY')
            self._precheck_current(db, assessment)
            original_rows = self._precheck_original_rows(db)
            try:
                observed = observer(binding, assessment['session'])
            except Exception:
                raise RecoveryError('PRECHECK_FRESH_OBSERVATION_UNCONFIRMED') from None
            _need(type(observed) is dict and canonical_bytes(observed) == assessment_raw,
                  'PRECHECK_FRESH_OBSERVATION_CHANGED')
            self._precheck_current(db, assessment)
            value = {'job_id': binding.job_id, 'assessment_sha256': expected_sha256,
                'assessment_raw': assessment_raw, 'legacy_record_sha256': assessment['legacy_record_sha256'],
                'closed_at_utc': _clock(now).isoformat()}
            value['record_sha256'] = self._record_hash(value)
            db.execute('INSERT INTO ' + self._PRECHECK_TABLE + ' VALUES(' +
                       ','.join('?' for _ in value) + ')', tuple(value[key] for key in self._PRECHECK_COLUMNS))
            closed = self._closed_precheck(db, binding.job_id)
            _need(self._precheck_original_rows(db) == original_rows, 'PRECHECK_ORIGINAL_ROWS_CHANGED')
            return {**closed, 'action': 'RECORDED_ONCE', 'original_rows_unchanged': True}

    # Distinct from both completed-browser failures and pre-import prechecks:
    # a clean application exists, but a positive dependency failure preceded
    # any QA staging/launch. Never manufacture a browser result or retry grant.
    _QA_STAGE_TABLE = 'verification_qa_stage_failures'
    _QA_STAGE_COLUMNS = ('job_id', 'assessment_sha256', 'assessment_raw',
        'legacy_record_sha256', 'closed_at_utc', 'record_sha256')

    @classmethod
    def _qa_stage_definitions(cls):
        table = cls._QA_STAGE_TABLE
        result = {('table', table): 'CREATE TABLE IF NOT EXISTS ' + table + '''(
            job_id TEXT PRIMARY KEY REFERENCES verification_queue(job_id),
            assessment_sha256 TEXT NOT NULL UNIQUE,assessment_raw BLOB NOT NULL,
            legacy_record_sha256 TEXT NOT NULL,closed_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)'''}
        for action in ('UPDATE', 'DELETE'):
            name = table + '_no_' + action.lower()
            result[('trigger', name)] = ('CREATE TRIGGER IF NOT EXISTS ' + name + ' BEFORE ' +
                action + ' ON ' + table + " BEGIN SELECT RAISE(ABORT,'QA-stage failure history is append-only'); END")
        return result

    @classmethod
    def _qa_stage_schema(cls, db, *, create=False):
        expected = cls._qa_stage_definitions()
        rows = [tuple(row) for row in db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','trigger')")
            if row[2] == cls._QA_STAGE_TABLE or (row[0], row[1]) in expected]
        if not rows:
            if not create:
                return False
            _need(db.in_transaction, 'QA_STAGE_SCHEMA_TRANSACTION_REQUIRED')
            for sql in expected.values(): db.execute(sql)
            return cls._qa_stage_schema(db)
        actual = {(row[0], row[1]): row[3] for row in rows}
        _need(set(actual) == set(expected) and all(
            cls.normalized_schema_sql(actual[key]) == cls.normalized_schema_sql(sql)
            for key, sql in expected.items()), 'QA_STAGE_SCHEMA_OR_FENCES_CHANGED')
        _need(tuple(row[1] for row in db.execute('PRAGMA table_info(' + cls._QA_STAGE_TABLE + ')'))
              == cls._QA_STAGE_COLUMNS, 'QA_STAGE_SCHEMA_COLUMNS_CHANGED')
        return True

    def initialize_qa_stage_failure_ledger(self, *, apply=False):
        _need(apply is True, 'QA_STAGE_EXPLICIT_INITIALIZATION_REQUIRED')
        with self._db(True) as db:
            db.execute('SELECT job_id,record_sha256 FROM verification_queue LIMIT 0')
            existed = self._qa_stage_schema(db)
            self._qa_stage_schema(db, create=True)
            return {'status': 'QA_STAGE_FAILURE_LEDGER_READY', 'created': not existed,
                    'technical_success': False, 'automatic_retry_permitted': False}

    @staticmethod
    def _qa_stage_assessment(value):
        fields = {'schema_version','scope','status','binding','session','installation_sha256',
            'legacy_record_sha256','claim_sha256','retained_sha256','clean_sha256','capture_sha256',
            'plan_sha256','qa_source_sha256','completed_steps','failed_phase','missing_dependency',
            'target','expected_versions','current_admission_blocks','closure_performed',
            'technical_success','human_acceptance_recorded','automatic_replay_permitted','recovery_authorized'}
        _need(type(value) is dict and set(value) == fields, 'QA_STAGE_ASSESSMENT_FIELDS')
        _need(type(value['schema_version']) is int and value['schema_version'] == 1
              and value['scope'] == 'fox-project-qa-stage-failure-assessment-v1'
              and value['status'] == 'CLASSIFIED_QA_STAGE_FAILURE_NOT_CLOSED'
              and value['failed_phase'] == 'qa_stage' and value['missing_dependency'] == 'fox.native_verification'
              and value['completed_steps'] == ['prepare','clean_check','allocate','schema','import','verify']
              and value['current_admission_blocks'] is True
              and all(value[k] is False for k in ('closure_performed','technical_success',
                  'human_acceptance_recorded','automatic_replay_permitted','recovery_authorized')),
              'QA_STAGE_ASSESSMENT_NOT_FAILURE')
        binding = VerificationBinding.from_payload(value['binding'])
        _need(type(value['session']) is str and _SESSION.fullmatch(value['session'])
              and all(_sha(value[k]) for k in ('installation_sha256','legacy_record_sha256',
                  'claim_sha256','capture_sha256','plan_sha256','qa_source_sha256')),
              'QA_STAGE_ASSESSMENT_BINDING')
        retained, clean = value['retained_sha256'], value['clean_sha256']
        journal_names = {'session.json','attention.json','p0001-qa-stage.intent.json',
            *('p0001-'+step+suffix for step in ('claim','prepare','clean-check','allocate','schema','import','verify')
              for suffix in ('.intent.json','.complete.json'))}
        clean_names = {'package.zip','native-project-spec.json','source-to-apex.json',
            'allocate.evidence.json','verification-profile.json','verify.evidence.json','plan.json',
            'schema.evidence.json','import.evidence.json',
            *(phase+suffix for phase in ('allocate','schema','import','verify')
              for suffix in ('.intent.json','.complete.json'))}
        _need(type(retained) is dict and set(retained) == journal_names
              and type(clean) is dict and set(clean) == clean_names
              and all(_sha(item) for item in (*retained.values(),*clean.values()))
              and clean['package.zip'] == binding.package_sha256
              and clean['plan.json'] == value['plan_sha256'], 'QA_STAGE_MANIFEST_CHANGED')
        # Historical failure reads preserve the exact recorded version tuple;
        # they grant no new technical decision or application operation.
        policy = BoundVerificationPolicy(canonical_bytes({'schema_version':1,
            'scope':'fox-native-verification-profile-v2','policy_id':POLICY_ID,
            'binding':{k:v for k,v in binding.payload().items() if k!='verifier_release_sha256'}
                | {'allocation_receipt_sha256':clean['allocate.evidence.json']},
            'target':value['target'],'expected_versions':value['expected_versions'],
            'max_evidence_age_seconds':86400}), historical=True)
        _need(policy.sha256 == clean['verification-profile.json'], 'QA_STAGE_POLICY_CHANGED')
        return binding

    def _qa_stage_current(self, db, assessment):
        binding = self._qa_stage_assessment(assessment)
        row = VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?',
                                                    (binding.job_id,)).fetchone())
        _need(row is not None and row['state'] == 'attention' and row['proof_sha256'] is None
              and row['attention_code'] == 'BACKEND_OUTCOME_UNCONFIRMED'
              and row['record_sha256'] == assessment['legacy_record_sha256']
              and all(row[k] == v for k,v in binding.payload().items())
              and claim_sha256(Claim(binding,row['claim_token'])) == assessment['claim_sha256'],
              'QA_STAGE_ORIGINAL_QUEUE_CHANGED')
        self._server_run(db,binding,unverified=True)
        snapshot = _load((self.database.parent/'jobs'/binding.job_id/'source-snapshot.json').read_bytes())
        _need(snapshot.get('conversion_profile') == 'native-project-v1','QA_STAGE_PROJECT_PROFILE_REQUIRED')
        return binding

    def _closed_qa_stage(self, db, job_id):
        if not self._qa_stage_schema(db):
            return None
        row = db.execute('SELECT * FROM '+self._QA_STAGE_TABLE+' WHERE job_id=?',(job_id,)).fetchone()
        if row is None:
            return None
        value = dict(row)
        _need(set(value) == set(self._QA_STAGE_COLUMNS) and type(value['assessment_raw']) is bytes
              and value['record_sha256'] == self._record_hash(value)
              and digest(value['assessment_raw']) == value['assessment_sha256'], 'QA_STAGE_LEDGER_ROW_CHANGED')
        assessment = _load(value['assessment_raw'])
        self._qa_stage_assessment(assessment)
        _need(canonical_bytes(assessment) == value['assessment_raw']
              and assessment['binding']['job_id'] == value['job_id']
              and assessment['legacy_record_sha256'] == value['legacy_record_sha256'],
              'QA_STAGE_LEDGER_DOCUMENT_CHANGED')
        _time(value['closed_at_utc'])
        self._qa_stage_current(db,assessment)
        return {'status':'FAILED_QA_STAGE_CLOSED','job_id':job_id,
                'assessment_sha256':value['assessment_sha256'],'technical_success':False,
                'human_acceptance_recorded':False,'automatic_retry_permitted':False}

    def close_qa_stage_failure(self, assessment_raw, *, expected_sha256, observer=None, apply=False, now=None):
        """Protected append only; no phase completion, import or retry is run.

        The caller must own real host exclusion and a complete recovery export.
        observer(binding, session) must freshly re-capture/re-classify under that
        exclusion. This method cannot obtain or replace that host authority.
        """
        _need(apply is True and callable(observer),'QA_STAGE_PROTECTED_OBSERVER_REQUIRED')
        _need(type(assessment_raw) is bytes and 0<len(assessment_raw)<=65536
              and _sha(expected_sha256) and digest(assessment_raw)==expected_sha256,
              'QA_STAGE_EXACT_REVIEWED_ASSESSMENT_REQUIRED')
        assessment = _load(assessment_raw);binding = self._qa_stage_assessment(assessment)
        _need(canonical_bytes(assessment)==assessment_raw,'QA_STAGE_CANONICAL_ASSESSMENT_REQUIRED')
        with self._db(True) as db:
            _need(self._qa_stage_schema(db),'QA_STAGE_EXPLICIT_LEDGER_INITIALIZATION_REQUIRED')
            existing = self._closed_qa_stage(db,binding.job_id)
            if existing:
                _need(existing['assessment_sha256']==expected_sha256,'QA_STAGE_DIFFERENT_CLOSURE_EXISTS')
                return {**existing,'action':'ALREADY_RECORDED_NO_REPLAY'}
            _need(self._closed_precheck(db,binding.job_id) is None and self._closed_project_prewrite(db,binding.job_id) is None,
                  'QA_STAGE_CONFLICTING_RECOVERY_HISTORY')
            if self._recovery_available(db):
                _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?',(binding.job_id,)).fetchone() is None
                      and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?',(binding.job_id,)).fetchone() is None,
                      'QA_STAGE_CONFLICTING_RECOVERY_HISTORY')
            self._qa_stage_current(db,assessment);original = self._precheck_original_rows(db)
            try:
                observed = observer(binding,assessment['session'])
            except Exception:
                raise RecoveryError('QA_STAGE_FRESH_OBSERVATION_UNCONFIRMED') from None
            _need(type(observed) is dict and canonical_bytes(observed)==assessment_raw,'QA_STAGE_FRESH_OBSERVATION_CHANGED')
            self._qa_stage_current(db,assessment)
            value={'job_id':binding.job_id,'assessment_sha256':expected_sha256,'assessment_raw':assessment_raw,
                'legacy_record_sha256':assessment['legacy_record_sha256'],'closed_at_utc':_clock(now).isoformat()}
            value['record_sha256']=self._record_hash(value)
            db.execute('INSERT INTO '+self._QA_STAGE_TABLE+' VALUES('+','.join('?' for _ in value)+')',
                       tuple(value[k] for k in self._QA_STAGE_COLUMNS))
            result=self._closed_qa_stage(db,binding.job_id)
            _need(self._precheck_original_rows(db)==original,'QA_STAGE_ORIGINAL_ROWS_CHANGED')
            return {**result,'action':'RECORDED_ONCE','original_rows_unchanged':True}

    # Completed project QA failed before a business-write dispatch. This is a
    # separate 22-file transcript; old native/7/17 contracts remain unchanged.
    _PROJECT_PREWRITE_TABLE = 'verification_project_prewrite_failures'
    _PROJECT_PREWRITE_COLUMNS = ('job_id','assessment_sha256','assessment_raw',
        'legacy_record_sha256','closed_at_utc','record_sha256')

    @classmethod
    def _project_prewrite_definitions(cls):
        table=cls._PROJECT_PREWRITE_TABLE
        result={('table',table):'CREATE TABLE IF NOT EXISTS '+table+'''(
            job_id TEXT PRIMARY KEY REFERENCES verification_queue(job_id),
            assessment_sha256 TEXT NOT NULL UNIQUE,assessment_raw BLOB NOT NULL,
            legacy_record_sha256 TEXT NOT NULL,closed_at_utc TEXT NOT NULL,record_sha256 TEXT NOT NULL)'''}
        for action in ('UPDATE','DELETE'):
            name=table+'_no_'+action.lower()
            result[('trigger',name)]=('CREATE TRIGGER IF NOT EXISTS '+name+' BEFORE '+action+' ON '+table+
                " BEGIN SELECT RAISE(ABORT,'project prewrite history is append-only'); END")
        return result

    @classmethod
    def _project_prewrite_schema(cls, db, *, create=False):
        expected=cls._project_prewrite_definitions();table=cls._PROJECT_PREWRITE_TABLE
        rows=[tuple(row) for row in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','trigger')")
            if row[2]==table or (row[0],row[1]) in expected]
        if not rows:
            if not create:return False
            _need(db.in_transaction,'PROJECT_PREWRITE_SCHEMA_TRANSACTION_REQUIRED')
            for sql in expected.values():db.execute(sql)
            return cls._project_prewrite_schema(db)
        actual={(row[0],row[1]):row[3] for row in rows}
        _need(set(actual)==set(expected) and all(cls.normalized_schema_sql(actual[key])==cls.normalized_schema_sql(sql)
            for key,sql in expected.items()),'PROJECT_PREWRITE_SCHEMA_OR_FENCES_CHANGED')
        _need(tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')'))==cls._PROJECT_PREWRITE_COLUMNS,
            'PROJECT_PREWRITE_SCHEMA_COLUMNS_CHANGED')
        return True

    def initialize_project_prewrite_ledger(self, *, apply=False):
        _need(apply is True,'PROJECT_PREWRITE_EXPLICIT_INITIALIZATION_REQUIRED')
        with self._db(True) as db:
            db.execute('SELECT job_id,record_sha256 FROM verification_queue LIMIT 0')
            existed=self._project_prewrite_schema(db);self._project_prewrite_schema(db,create=True)
            return {'status':'PROJECT_PREWRITE_LEDGER_READY','created':not existed,
                'technical_success':False,'automatic_retry_permitted':False}

    @staticmethod
    def _project_prewrite_assessment(value):
        fields={'schema_version','scope','status','binding','session','installation_sha256','legacy_record_sha256',
            'claim_sha256','retained_sha256','clean_sha256','collection_sha256','capture_sha256','plan_sha256',
            'qa_source_sha256','qa_image','qa_run_id','qa_report_sha256','retained_steps','failed_phase','dispatch_state',
            'target','expected_versions','current_admission_blocks','closure_performed','technical_success',
            'human_acceptance_recorded','automatic_replay_permitted','recovery_authorized'}
        _need(type(value) is dict and set(value)==fields,'PROJECT_PREWRITE_ASSESSMENT_FIELDS')
        _need(type(value['schema_version']) is int and value['schema_version']==1
            and value['scope']=='fox-project-prewrite-qa-assessment-v1'
            and value['status']=='CLASSIFIED_PROJECT_PREWRITE_QA_NOT_CLOSED' and value['failed_phase']=='qa_run'
            and value['dispatch_state']=='PREFLIGHT_BLOCKED' and value['retained_steps']==list(PHASES)
            and value['current_admission_blocks'] is True and all(value[k] is False for k in
                ('closure_performed','technical_success','human_acceptance_recorded','automatic_replay_permitted','recovery_authorized')),
            'PROJECT_PREWRITE_ASSESSMENT_NOT_FAILURE')
        binding=VerificationBinding.from_payload(value['binding'])
        _need(type(value['session']) is str and _SESSION.fullmatch(value['session'])
            and all(_sha(value[k]) for k in ('installation_sha256','legacy_record_sha256','claim_sha256','capture_sha256',
                'plan_sha256','qa_source_sha256','qa_report_sha256'))
            and type(value['qa_image']) is str and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',value['qa_image'])
            and type(value['qa_run_id']) is str and re.fullmatch(r'FPQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}',value['qa_run_id']),
            'PROJECT_PREWRITE_ASSESSMENT_BINDING')
        journal={'session.json','attention.json',*('p0001-'+step.replace('_','-')+suffix for step in ('claim',*PHASES)
            for suffix in ('.intent.json','.complete.json'))}
        clean={'package.zip','native-project-spec.json','source-to-apex.json','allocate.evidence.json','verification-profile.json',
            'verify.evidence.json','plan.json','schema.evidence.json','import.evidence.json',
            *(phase+suffix for phase in ('allocate','schema','import','verify') for suffix in ('.intent.json','.complete.json'))}
        collection={'package.zip','native-project-spec.json','source-to-apex.json','allocation-receipt.json',
            'verification-profile.json','clean-import-receipt.json','qa-profile.json','target-receipt.json','qa-result.json',
            'stage-receipt.json','launch-intent.json','launch-receipt.json','collection-manifest.json'}
        for key,expected in (('retained_sha256',journal),('clean_sha256',clean),('collection_sha256',collection)):
            _need(type(value[key]) is dict and set(value[key])==expected and all(_sha(v) for v in value[key].values()),
                'PROJECT_PREWRITE_MANIFEST_CHANGED')
        a,b=value['clean_sha256'],value['collection_sha256']
        pairs={'package.zip':'package.zip','native-project-spec.json':'native-project-spec.json','source-to-apex.json':'source-to-apex.json',
            'allocation-receipt.json':'allocate.evidence.json','verification-profile.json':'verification-profile.json','clean-import-receipt.json':'verify.evidence.json'}
        _need(a['package.zip']==binding.package_sha256 and a['plan.json']==value['plan_sha256']
            and b['qa-result.json']==value['qa_report_sha256'] and all(b[key]==a[original] for key,original in pairs.items()),
            'PROJECT_PREWRITE_CROSS_MANIFEST_CHANGED')
        policy=BoundVerificationPolicy(canonical_bytes({'schema_version':1,'scope':'fox-native-verification-profile-v2','policy_id':POLICY_ID,
            'binding':{k:v for k,v in binding.payload().items() if k!='verifier_release_sha256'}|{'allocation_receipt_sha256':a['allocate.evidence.json']},
            'target':value['target'],'expected_versions':value['expected_versions'],'max_evidence_age_seconds':86400}),historical=True)
        _need(policy.sha256==a['verification-profile.json'],'PROJECT_PREWRITE_POLICY_CHANGED')
        return binding

    def _project_prewrite_current(self, db, assessment):
        binding=self._project_prewrite_assessment(assessment)
        row=VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?',(binding.job_id,)).fetchone())
        _need(row is not None and row['state']=='attention' and row['proof_sha256'] is None
            and row['attention_code']=='BACKEND_OUTCOME_UNCONFIRMED' and row['record_sha256']==assessment['legacy_record_sha256']
            and all(row[k]==v for k,v in binding.payload().items())
            and claim_sha256(Claim(binding,row['claim_token']))==assessment['claim_sha256'],'PROJECT_PREWRITE_ORIGINAL_QUEUE_CHANGED')
        self._server_run(db,binding,unverified=True)
        snapshot=_load((self.database.parent/'jobs'/binding.job_id/'source-snapshot.json').read_bytes())
        _need(snapshot.get('conversion_profile')=='native-project-v1','PROJECT_PREWRITE_PROJECT_PROFILE_REQUIRED')
        return binding

    def _closed_project_prewrite(self, db, job_id):
        if not self._project_prewrite_schema(db):return None
        row=db.execute('SELECT * FROM '+self._PROJECT_PREWRITE_TABLE+' WHERE job_id=?',(job_id,)).fetchone()
        if row is None:return None
        value=dict(row)
        _need(set(value)==set(self._PROJECT_PREWRITE_COLUMNS) and type(value['assessment_raw']) is bytes
            and value['record_sha256']==self._record_hash(value) and digest(value['assessment_raw'])==value['assessment_sha256'],
            'PROJECT_PREWRITE_LEDGER_ROW_CHANGED')
        assessment=_load(value['assessment_raw']);self._project_prewrite_assessment(assessment)
        _need(canonical_bytes(assessment)==value['assessment_raw'] and assessment['binding']['job_id']==job_id
            and assessment['legacy_record_sha256']==value['legacy_record_sha256'],'PROJECT_PREWRITE_LEDGER_DOCUMENT_CHANGED')
        _time(value['closed_at_utc']);self._project_prewrite_current(db,assessment)
        return {'status':'FAILED_PROJECT_PREWRITE_QA_CLOSED','job_id':job_id,'assessment_sha256':value['assessment_sha256'],
            'technical_success':False,'human_acceptance_recorded':False,'automatic_retry_permitted':False}

    def close_project_prewrite_failure(self, assessment_raw, *, expected_sha256, observer=None, apply=False, now=None):
        """Append failure only; caller must hold real host exclusion and recovery export.

        The observer freshly captures/classifies inside this reserved transaction.
        This method neither creates nor substitutes for the current-I OS lease.
        No original run/queue/claim, application or phase is completed or replayed.
        """
        _need(apply is True and callable(observer),'PROJECT_PREWRITE_PROTECTED_OBSERVER_REQUIRED')
        _need(type(assessment_raw) is bytes and 0<len(assessment_raw)<=65536 and _sha(expected_sha256)
            and digest(assessment_raw)==expected_sha256,'PROJECT_PREWRITE_EXACT_ASSESSMENT_REQUIRED')
        assessment=_load(assessment_raw);binding=self._project_prewrite_assessment(assessment)
        _need(canonical_bytes(assessment)==assessment_raw,'PROJECT_PREWRITE_CANONICAL_ASSESSMENT_REQUIRED')
        with self._db(True) as db:
            _need(self._project_prewrite_schema(db),'PROJECT_PREWRITE_EXPLICIT_LEDGER_INITIALIZATION_REQUIRED')
            existing=self._closed_project_prewrite(db,binding.job_id)
            if existing:
                _need(existing['assessment_sha256']==expected_sha256,'PROJECT_PREWRITE_DIFFERENT_CLOSURE_EXISTS')
                return {**existing,'action':'ALREADY_RECORDED_NO_REPLAY'}
            _need(self._closed_precheck(db,binding.job_id) is None and self._closed_qa_stage(db,binding.job_id) is None,
                'PROJECT_PREWRITE_CONFLICTING_RECOVERY_HISTORY')
            if self._recovery_available(db):
                _need(db.execute('SELECT 1 FROM verification_failed_dispositions WHERE job_id=?',(binding.job_id,)).fetchone() is None
                    and db.execute('SELECT 1 FROM verification_retry_attempts WHERE job_id=?',(binding.job_id,)).fetchone() is None,
                    'PROJECT_PREWRITE_CONFLICTING_RECOVERY_HISTORY')
            self._project_prewrite_current(db,assessment);original=self._precheck_original_rows(db)
            try:observed=observer(binding,assessment['session'])
            except Exception:raise RecoveryError('PROJECT_PREWRITE_FRESH_OBSERVATION_UNCONFIRMED') from None
            _need(type(observed) is dict and canonical_bytes(observed)==assessment_raw,'PROJECT_PREWRITE_FRESH_OBSERVATION_CHANGED')
            self._project_prewrite_current(db,assessment)
            value={'job_id':binding.job_id,'assessment_sha256':expected_sha256,'assessment_raw':assessment_raw,
                'legacy_record_sha256':assessment['legacy_record_sha256'],'closed_at_utc':_clock(now).isoformat()}
            value['record_sha256']=self._record_hash(value)
            db.execute('INSERT INTO '+self._PROJECT_PREWRITE_TABLE+' VALUES('+','.join('?' for _ in value)+')',
                tuple(value[k] for k in self._PROJECT_PREWRITE_COLUMNS))
            result=self._closed_project_prewrite(db,binding.job_id)
            _need(self._precheck_original_rows(db)==original,'PROJECT_PREWRITE_ORIGINAL_ROWS_CHANGED')
            return {**result,'action':'RECORDED_ONCE','original_rows_unchanged':True}

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
            _need(self._closed_precheck(db,claim.binding.job_id) is None
                  and self._closed_qa_stage(db,claim.binding.job_id) is None
                  and self._closed_project_prewrite(db,claim.binding.job_id) is None,
                  'RECOVERY_CONFLICTING_FAILURE_FAMILY')
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
        prewrite = self._closed_project_prewrite(db,job_id)
        if prewrite is not None:
            _need(closed is None and retry is None and self._closed_precheck(db,job_id) is None
                  and self._closed_qa_stage(db,job_id) is None,'PROJECT_PREWRITE_CONFLICTING_RECOVERY_HISTORY')
            return {'blocks_admission':False,'recovery_state':'project_prewrite_failed_closed','retry_eligible':False}
        precheck = self._closed_precheck(db, job_id)
        if precheck is not None:
            _need(closed is None and retry is None and self._closed_qa_stage(db,job_id) is None,
                  'PRECHECK_CONFLICTING_RECOVERY_HISTORY')
            return {'blocks_admission': False, 'recovery_state': 'precheck_failed_closed', 'retry_eligible': False}
        stage = self._closed_qa_stage(db,job_id)
        if stage is not None:
            _need(closed is None and retry is None,'QA_STAGE_CONFLICTING_RECOVERY_HISTORY')
            return {'blocks_admission':False,'recovery_state':'qa_stage_failed_closed','retry_eligible':False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None
                and closed is None and retry is None
                and terminal_empty_prototype_mapping(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_mapping_incomplete',
                    'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_empty_prototype_mapping(self.database, db, dict(run), claim_owner_failure=True)):
            return {'blocks_admission': False, 'recovery_state': 'prototype_mapping_owner_resolution_pending', 'retry_eligible': False}
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
        if self._precheck_schema(db):
            query += ' UNION SELECT job_id FROM '+self._PRECHECK_TABLE
        if self._qa_stage_schema(db):
            query += ' UNION SELECT job_id FROM '+self._QA_STAGE_TABLE
        if self._project_prewrite_schema(db):
            query += ' UNION SELECT job_id FROM '+self._PROJECT_PREWRITE_TABLE
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
            _need(self._closed_project_prewrite(db,binding.job_id) is None,'PROJECT_PREWRITE_NORMAL_REPLAY_FORBIDDEN')
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
