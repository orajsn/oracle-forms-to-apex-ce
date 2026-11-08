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


def terminal_empty_prototype_mapping(database, db, run, *, claim_owner_failure=False,
                                     analysis_epoch_failure=False, clause_repair_failure=False,
                                     container_review_failure=False, partition_review_failure=False,
                                     context_screen_failure=False, review_scope_failure=False,
                                     post_correction_review_failure=False):
    """Recognize one sealed first EMPTY mapper, not success or retry authority.

    Deliberately self-contained stdlib: the transition bridge loads this
    reviewed module in the serving legacy namespace, which has no new prototype
    modules. Producer-held durable bindings are checked here; fresh XML semantic
    reconstruction and current processing consent remain the recovery API's job.
    The opt-in analysis family proves only a sealed, pre-database stop after an
    immutable v1 continuation. Historical AI approval is NOT source-fact truth.
    New epoch eligibility and processing consent must be checked separately.
    The separate clause-repair family accepts only epoch two's sealed mapper
    deleting both defective claims without replacing their required behavior.
    It validates the immutable consent/baseline chain, never calls epoch runtime
    helpers, and grants no execution, retry, reuse, export or success authority.
    The epoch-three branch checks sealed structural provenance, not clause
    semantics or approval for reuse/adoption. Those remain later semantic gates.
    No mutable epoch-head selector, runtime client or archived Python is used.
    The separate epoch-four opt-in recognizes only its sealed unchanged rejection
    and complete result publication. Outside-job reviews grant no authority here.
    The epoch-five opt-in preserves the known pre-review duplicate-screen stop,
    including the absence of a new result publication. It never projects a design.
    The epoch-six opt-in recognizes only the sealed non-owned context-Block
    attribution defect. It does not accept the review or authorize correction.
    Unknown/missing/extra evidence and all later work remain blocking.
    A distinct opt-in preserves the complete original167 checkpoint and then
    checks its consumed correction and sealed14-section negative publication.
    This grants preservation/admission classification only, never retry/approval.
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
        source = (job / 'prototype-result-publications/epoch-000006/previous-result.json'
                  if archived_latest and path == job / 'prototype-result.json' else path)
        protected(source)
        need(source.is_file() and not source.is_symlink() and source.stat().st_nlink == 1
             and 0 < source.stat().st_size <= maximum)
        raw = source.read_bytes()
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
        need(all(type(value) is bool for value in
                 (claim_owner_failure, analysis_epoch_failure, clause_repair_failure,
                  container_review_failure, partition_review_failure, context_screen_failure, review_scope_failure,
                  post_correction_review_failure))
             and sum((claim_owner_failure, analysis_epoch_failure, clause_repair_failure,
                      container_review_failure, partition_review_failure, context_screen_failure, review_scope_failure,
                      post_correction_review_failure)) <= 1)
        archived_latest = post_correction_review_failure
        review_scope_failure = review_scope_failure or post_correction_review_failure
        screen_family = context_screen_failure or review_scope_failure
        partition_family = partition_review_failure or screen_family
        container_family = container_review_failure or partition_family
        clause_family = clause_repair_failure or container_family
        analysis_family = analysis_epoch_failure or clause_family
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
        if (claim_owner_failure or analysis_family) and 'retry_of' in snapshot:
            snapshot_keys.update(('retry_of', 'mapping_recovery'))
            parent, metadata = snapshot['retry_of'], snapshot['mapping_recovery']
            need(type(parent) is str and re.fullmatch(r'fox-[a-f0-9]{20}', parent)
                 and run['id'] == 'fox-' + hashed({'parent_run_id': parent, 'strategy': 'repartition-32-v1'})[:20]
                 and type(metadata) is dict and set(metadata) == {'schema_version', 'strategy', 'parent_snapshot_sha256'}
                 and type(metadata['schema_version']) is int and metadata['schema_version'] == 1
                 and metadata['strategy'] == 'repartition-32-v1' and sha(metadata['parent_snapshot_sha256']))
        need(type(claim_owner_failure) is bool and type(analysis_epoch_failure) is bool
             and not (claim_owner_failure and analysis_epoch_failure) and set(snapshot) == snapshot_keys
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
        if claim_owner_failure or analysis_family:
            need(1 <= len(focuses) <= 256)
            continuation = None
            if analysis_family:
                need(version == 2 and len(focuses) == 8)
                continuation = document(job / 'mapping-continuation.json')
                need(set(continuation) == {'schema_version', 'scope', 'strategy', 'job_id', 'project_id',
                    'snapshot_sha256', 'checkpoint_sha256', 'files', 'completed_focuses', 'blocked_focus_id',
                    'resolved_claim_owners', 'owner', 'approved_at', 'approvals'}
                    and type(continuation['schema_version']) is int and continuation['schema_version'] == 1
                    and continuation['scope'] == 'fox-prototype-mapping-continuation-v1'
                    and continuation['strategy'] == 'resolve-code-unit-owners-v1'
                    and continuation['job_id'] == run['id'] and continuation['project_id'] == run['project']
                    and continuation['snapshot_sha256'] == hashlib.sha256(observed['source-snapshot.json']).hexdigest()
                    and continuation['owner'] == owner[0]
                    and type(continuation['approved_at']) in (int, float)
                    and math.isfinite(continuation['approved_at']) and continuation['approved_at'] > 0
                    and type(continuation['completed_focuses']) is int and continuation['completed_focuses'] == 5
                    and type(continuation['resolved_claim_owners']) is int
                    and 1 <= continuation['resolved_claim_owners'] <= 10000
                    and type(continuation['files']) is dict and 1 <= len(continuation['files']) <= 4096)
                same(continuation['approvals'], {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True})
                proof = {key: continuation[key] for key in
                    ('files', 'completed_focuses', 'blocked_focus_id', 'resolved_claim_owners')}
                need(hashed(proof) == continuation['checkpoint_sha256'])
                events = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
                    '(object_id=? OR object_id LIKE ?)', ('approved_prototype_mapping_continuation',
                    run['id'], run['id'] + ':%')).fetchall()
                need([tuple(row) for row in events] == [(owner[0], run['id'] + ':' + hashed(continuation), continuation['approved_at'])])
                if not clause_family:
                    need(db.execute('SELECT 1 FROM events WHERE action=? AND (object_id=? OR object_id LIKE ?) LIMIT 1',
                        ('approved_prototype_mapping_epoch', run['id'], run['id'] + ':%')).fetchone() is None)
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

            def role_output(directory, name, payload, role_target=None):
                effective_target = target if role_target is None else role_target
                same(document(directory / (name + '-target.json')), effective_target)
                saved = document(directory / (name + '.json'))
                need(set(saved) == {'binding', 'output', 'output_sha256', 'invocation', 'model_environment', 'model_environment_sha256'})
                role = effective_target['opaf']['roles'][name]
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
                    'target_profile_sha256': hashed(effective_target), 'observed_at_utc': environment['observed_at_utc'],
                    'opaf': {key: effective_target['opaf'][key] for key in ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                    'workflow': {**role, 'published': True}, 'opaf_version': effective_target['tested_versions']['opaf']})
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
            prefix, checkpoint_files, resolution_count = [], set(), 0
            if analysis_family:
                checkpoint_files = set(observed) - {'mapping-continuation.json'}
                # Request files have already been read while ordering focuses;
                # only the first six existed at the immutable v1 checkpoint.
                checkpoint_files -= {'prototype-pipeline/' + directory.name + '/request.json'
                                     for _, directory in requests[6:]}
                checkpoint_files.add('prototype-pipeline/assessment.json')
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
                if analysis_family:
                    if number < 6:
                        checkpoint_files.update('prototype-pipeline/' + directory.name + '/' + name for name in
                            ('mapper.json', 'mapper-target.json', 'mapper-intent.json'))
                    if number < 5:
                        checkpoint_files.update('prototype-pipeline/' + directory.name + '/' + name for name in
                            ('reviewer.json', 'reviewer-target.json', 'reviewer-intent.json', 'review-receipt.json'))
                    if number == 5:
                        need(request['focus_id'] == continuation['blocked_focus_id'])
                        raw = candidate
                        candidate = json.loads(canonical(raw)); changes = []
                        units = {unit['id']: unit for unit in request['code_units']}
                        object_ids = [row['id'] for row in request['owned_objects'] + request['context_objects']]
                        need(len(units) == len(request['code_units']) and len(set(object_ids)) == len(object_ids)
                             and not set(units) & set(object_ids))
                        for index, claim in enumerate(candidate['blueprint']['claims']):
                            ref = claim['source_object_id']
                            if ref in owned_ids: continue
                            unit, refs = units[ref], claim['evidence_refs']
                            need(unit['owner_id'] in owned_ids and type(refs) is list and ref in refs
                                 and len(set(refs)) == len(refs) and all(value == unit['owner_id'] or
                                     value in units and units[value]['owner_id'] == unit['owner_id'] for value in refs))
                            claim['source_object_id'] = unit['owner_id']
                            changes.append({'claim_index': index, 'claim_id': claim['id'],
                                'code_unit_id': ref, 'source_object_id': unit['owner_id']})
                        resolution_count = len(changes)
                        need(resolution_count == continuation['resolved_claim_owners'])
                        same(document(directory / 'mapper-resolved.json'), candidate)
                        same(document(directory / 'mapper-resolution.json'), {'schema_version': 1,
                            'scope': 'fox-prototype-claim-owner-resolution-v1', 'strategy': 'resolve-code-unit-owners-v1',
                            'source_binding': request['source_binding'], 'focus_id': request['focus_id'],
                            'request_sha256': hashed(request), 'raw_candidate_sha256': hashed(raw),
                            'candidate_sha256': hashed(candidate), 'resolutions': changes})
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
                    if analysis_family:
                        need(number < 7)
                        # This is historical provenance, not a fact-validity
                        # gate. The new epoch must freshly diagnose/repair7.
                        prefix.append(candidate)
                else:
                    need(number == len(requests) - 1)
                    if analysis_family:
                        need(number == 7 and len(prefix) == 7 and resolution_count > 0)
                        # Recognize only the retained context/alias stop. This
                        # in-memory structural projection grants no resume or
                        # source-fact approval and is never saved as AI output.
                        projected = json.loads(canonical(candidate))
                        blueprint, prior = projected['blueprint'], prefix[-1]['blueprint']
                        extras = [row for row in blueprint['objects'] if row['source_object_id'] not in owned_ids]
                        need(len(extras) == 1)
                        extra = extras[0]; ref = extra['source_object_id']
                        context = {row['id']: row for row in request['context_objects']}
                        need(context[ref]['kind'] == 'Block')
                        matches = [row for row in prior['objects'] if row['source_object_id'] == ref]
                        need(len(matches) == 1)
                        same({key: value for key, value in extra.items() if key != 'reason'},
                             {key: value for key, value in matches[0].items() if key != 'reason'})
                        screen = extra['screen_id']
                        duplicates = [row for row in blueprint['screens'] if row['id'] == screen]
                        prior_screens = [row for row in prior['screens'] if row['id'] == screen]
                        need(len(duplicates) == len(prior_screens) == 1); same(duplicates, prior_screens)
                        excluded = [row for row in blueprint['claims'] if row['source_object_id'] not in owned_ids]
                        need(len(excluded) == 1)
                        claim = excluded[0]
                        need(claim['source_object_id'] == ref and claim['kind'] == 'object.kind'
                             and claim['status'] == 'source_fact' and claim['value'] == 'Block'
                             and claim['evidence_refs'] == [ref])
                        need(not any(claim['id'] in row['claim_ids'] for value in [candidate, *prefix]
                            for category in ('actions', 'relationships') for row in value['blueprint'][category]))
                        blueprint['objects'].remove(extra); blueprint['claims'].remove(claim)
                        blueprint['screens'] = [row for row in blueprint['screens'] if row['id'] != screen]
                        aliases = 0
                        for row in blueprint['claims']:
                            if row['kind'] == 'object.item_type' and row['status'] == 'source_fact':
                                obj = all_objects[row['source_object_id']]
                                need(obj['id'] in owned_ids and obj['kind'] == 'Item'
                                     and row['value'] == obj['item_type'] and row['evidence_refs'] == [obj['id']])
                                row['kind'] = 'item.item_type'; aliases += 1
                        need(aliases == 2); shape(projected, request, owned_ids)
                        failure = True
                        continue
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
            if analysis_family:
                need(set(continuation['files']) == checkpoint_files)
                same(continuation['files'], {name: hashlib.sha256(observed[name]).hexdigest() for name in checkpoint_files})
            epoch_directories = set()
            if clause_family:
                # Freeze the complete validated historical closure BEFORE reading
                # any epoch-selected descriptor. Unknown paths are never opened.
                baseline = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()}
                epoch_name = 'epoch-000002'
                epoch_prefix = 'prototype-pipeline/epochs/' + epoch_name
                repair_request = requests[6][0]
                projection_request = requests[7][0]
                epoch_directories = {'mapping-epochs', 'prototype-pipeline/epochs', epoch_prefix,
                    epoch_prefix + '/source-facts', epoch_prefix + '/' + repair_request['focus_id']}
                # Check every selected ancestor before reading epoch proof bytes.
                for name in sorted(epoch_directories, key=lambda value: (value.count('/'), value)):
                    path = job / name
                    need(path.is_dir()); protected(path)
                historical = prefix[6]
                bad_claims = [row for row in historical['blueprint']['claims'] if row['status'] == 'source_fact']
                need(len(bad_claims) == 2 and {row['kind'] for row in bad_claims} == {'block.where', 'block.order'}
                     and not any(row['status'] == 'source_fact' for value in prefix[:6]
                                 for row in value['blueprint']['claims']))
                diagnostics, required = [], []
                attributes = {'block.where': 'WhereClause', 'block.order': 'OrderByClause'}
                selected_units = {chunk['code_unit_id']: chunk for chunk in repair_request['chunks']}
                for index, claim in enumerate(historical['blueprint']['claims']):
                    if claim['status'] != 'source_fact':
                        continue
                    diagnostic = {'claim_index': index, 'claim_id': claim['id'], 'claim_sha256': hashed(claim),
                        'kind': claim['kind'], 'code': 'SOURCE_FACT_NOT_EXACT_WHITELISTED_EVIDENCE'}
                    diagnostics.append(diagnostic)
                    units = [unit for unit in repair_request['code_units'] if unit['owner_id'] == claim['source_object_id']
                        and unit['source_attribute'] == attributes[claim['kind']] and unit['id'] in selected_units]
                    need(len(units) == 1)
                    unit = units[0]; chunk = selected_units[unit['id']]
                    need(unit['sha256'] == chunk['sha256'] and 'FOX_REDACTED_' not in chunk['text']
                         and not any(row['kind'] == 'behavior.intent' and unit['id'] in row['evidence_refs']
                                     for row in historical['blueprint']['claims']))
                    required.append({'unit_id': unit['id'], 'owner_id': unit['owner_id'],
                        'source_attribute': unit['source_attribute'], 'unit_sha256': unit['sha256'],
                        'defective_claim_id': claim['id']})
                need(len({unit['unit_id'] for unit in required}) == 2)
                requirements = {'schema_version': 1, 'scope': 'fox-focus-clause-repair-requirements-v1',
                    'diagnostics': diagnostics, 'required_behavior_units': required,
                    'preserve_objects_screens_and_unrelated_design': True, 'exact_source_fact_whitelist_required': True,
                    'simple_status_relabeling_forbidden': True, 'each_required_unit_needs_behavior_intent_and_action': True,
                    'external_semantics_must_remain_uncertain': True, 'automatic_repair_loop_permitted': False}
                policy = {'source_facts': 'exact-existing-whitelist-v1',
                    'legacy_owner_resolution': 'resolve-code-unit-owners-v1-immutable',
                    'new_context_alias_projection': 'exact-active-owner-context-v2',
                    'future_mapper_repairs_permitted': False, 'continue_remaining_run': True}
                plan = {'ai_approved_focuses': 7, 'source_checked_focuses': 6,
                    'repair_focus_id': repair_request['focus_id'], 'projection_focus_id': projection_request['focus_id'],
                    'source_fact_violations': 2, 'planned_corrective_operations': ['mapper_repair', 'repair_review', 'projection_review'],
                    'remaining_focus_count': assessment['focus_count'] - 8, 'continue_remaining_run': True,
                    'repair_requirements': requirements, 'repair_raw_candidate_sha256': hashed(historical),
                    'projection_raw_candidate_sha256': hashed(candidate)}
                epoch = document(job / 'mapping-epochs' / (epoch_name + '.json'))
                expected = {'schema_version': 1, 'scope': 'fox-prototype-mapping-epoch-v1',
                    'strategy': 'repair-source-facts-and-project-context-v1', 'epoch_number': 2,
                    'predecessor_sha256': hashed(continuation),
                    'checkpoint_sha256': hashed({'epoch_number': 2, 'predecessor_sha256': hashed(continuation),
                        'before_files': baseline, 'plan': plan, 'normalization_policy': policy}),
                    'job_id': run['id'], 'project_id': run['project'],
                    'snapshot_sha256': hashlib.sha256(observed['source-snapshot.json']).hexdigest(),
                    'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                    'target_profile_sha256': selected['target_profile_sha256'], 'owner': owner[0],
                    'approved_at': epoch['approved_at'], 'approvals': {'redacted_source': True,
                        'external_ai': True, 'synthetic_prototype': True},
                    'before_files': baseline, 'plan': plan, 'normalization_policy': policy}
                need(type(epoch['approved_at']) in (int, float) and math.isfinite(epoch['approved_at'])
                     and epoch['approved_at'] >= continuation['approved_at']
                     and type(epoch['schema_version']) is int and type(epoch['epoch_number']) is int)
                same(epoch, expected)
                events = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
                    '(object_id=? OR object_id LIKE ?)', ('approved_prototype_mapping_epoch',
                    run['id'], run['id'] + ':%')).fetchall()
                epoch_two_event = (owner[0], run['id'] + ':epoch:000002:' + hashed(epoch), epoch['approved_at'])
                if container_family:
                    need(len(events) == (5 if review_scope_failure else 4 if context_screen_failure else 3 if partition_review_failure else 2)
                         and sum(tuple(row) == epoch_two_event for row in events) == 1)
                else:
                    need([tuple(row) for row in events] == [epoch_two_event])
                event_actions = db.execute('SELECT action FROM events WHERE object_id=? OR object_id LIKE ?',
                    (run['id'], run['id'] + ':%')).fetchall()
                need(sorted(row[0] for row in event_actions) == sorted((origin,
                    'approved_prototype_mapping_continuation', 'approved_prototype_mapping_epoch',
                    *(['approved_prototype_mapping_epoch'] * (4 if review_scope_failure else 3 if context_screen_failure else 2 if partition_review_failure else 1)
                      if container_family else []), *(['approved_prototype_review_scope_correction']
                      if post_correction_review_failure else []))))
                epoch_root = job / epoch_prefix
                same(document(epoch_root / 'epoch-record.json'), epoch)
                same(document(epoch_root / 'predecessor-record.json'), continuation)
                # The successful six unchanged prefixes acquired only fresh
                # deterministic source-fact receipts, not new model invocations.
                for (request, _), value in zip(requests[:6], prefix[:6]):
                    same(document(epoch_root / 'source-facts' / (request['focus_id'] + '.json')),
                        {'schema_version': 1, 'scope': 'fox-focus-source-fact-check-v1',
                         'source_binding': selected['source_binding'], 'request_sha256': hashed(request),
                         'candidate_sha256': hashed(value), 'source_facts_checked': True,
                         'source_fact_claims': 0, 'business_behavior_accepted': False})
                directory = epoch_root / repair_request['focus_id']
                payload = {**repair_request, 'repair_context': {'schema_version': 1,
                    'scope': 'fox-one-focus-mapper-repair-v1', 'original_request_sha256': hashed(repair_request),
                    'raw_candidate': historical, 'raw_candidate_sha256': hashed(historical), 'requirements': requirements,
                    'task': 'Return a replacement for this focus only. Analyze the supplied clauses; do not relabel invented facts. Preserve all unrelated design exactly.'}}
                same(document(directory / 'mapper-request.json'), payload)
                repaired, room = role_output(directory, 'mapper', payload)
                need(room not in rooms)
                shape(repaired, repair_request, {row['id'] for row in repair_request['owned_objects']})
                # Exact known failure, not arbitrary invalid repair: only those
                # two claims disappeared. All other bytes/fields/order survive.
                omitted = {row['defective_claim_id'] for row in required}
                expected_candidate = json.loads(canonical(historical))
                expected_candidate['blueprint']['claims'] = [row for row in historical['blueprint']['claims']
                    if row['id'] not in omitted]
                same(repaired, expected_candidate)
                need(len(omitted) == 2 and not any(ref in omitted for category in ('actions', 'relationships')
                    for row in repaired['blueprint'][category] for ref in row['claim_ids']))
            if container_family:
                # Admission-only structural provenance. Full semantic clause
                # reconstruction remains mandatory for any later adoption.
                # No additional runtime module/import/manifest closure is used.
                assembler_sha = 'b722fb5c851ca79da314d6a0412e06fe8190b09670e63b524fdb1c0c5780715a'
                json_names = {'diagnostic-intent.json', 'clause-request.json', 'derived-candidate.json',
                    'derived-assembly.json', 'assembly-binding.json', 'review-receipt.json', 'result.json',
                    *{folder + '/' + name + suffix for folder, name in (('analysis', 'mapper'), ('review', 'reviewer'))
                      for suffix in ('-intent.json', '-target.json', '.json')}}

                def gate(value, request, count):
                    return {'schema_version': 1, 'scope': 'fox-focus-source-fact-check-v1',
                        'source_binding': selected['source_binding'], 'request_sha256': hashed(request),
                        'candidate_sha256': hashed(value), 'source_facts_checked': True,
                        'source_fact_claims': count, 'business_behavior_accepted': False}

                def review_receipt(value, request, verdict):
                    return {'verdict': verdict, 'candidate_sha256': hashed(value),
                        'source_binding': selected['source_binding'], 'focus_binding': request['focus_binding'],
                        'approved_structured_design': verdict == 'APPROVED', **{key: False for key in
                        ('generation_ready', 'native_apex_generated', 'native_apex_validity_verified',
                         'import_verified', 'business_behavior_accepted')}}
                baseline_three = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()}
                third_prefix = 'prototype-pipeline/epochs/epoch-000003'
                third_dirs = {third_prefix, third_prefix + '/clause-proof',
                    third_prefix + '/clause-proof/analysis', third_prefix + '/clause-proof/review',
                    third_prefix + '/source-facts', third_prefix + '/' + projection_request['focus_id'],
                    'prototype-results'}
                for name in sorted(third_dirs, key=lambda value: (value.count('/'), value)):
                    path = job / name
                    need(path.is_dir()); protected(path)
                third_root = job / third_prefix
                descriptor = document(third_root / 'clause-proof-descriptor.json', 65_536)
                same({key: value for key, value in descriptor.items() if key not in
                      ('analysis_role', 'original_manifest', 'original_manifest_sha256', 'candidate_sha256')},
                    {'schema_version': 1, 'scope': 'fox-prototype-clause-proof-staging-v1',
                     'job_id': run['id'], 'project_id': run['project'], 'owner': owner[0],
                     'snapshot_sha256': hashlib.sha256(observed['source-snapshot.json']).hexdigest(),
                     'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                     'original_target_sha256': selected['target_profile_sha256'], 'assembler_sha256': assembler_sha})
                need(type(descriptor['schema_version']) is int
                     and hashed(descriptor['original_manifest']) == descriptor['original_manifest_sha256'])
                manifest = descriptor['original_manifest']
                need(type(manifest) is dict and set(manifest) == json_names | {'prototype_clause_analysis.py'})
                for pin in manifest.values():
                    need(type(pin) is dict and set(pin) == {'sha256', 'bytes'} and sha(pin['sha256'])
                         and type(pin['bytes']) is int and 0 < pin['bytes'] <= 2_000_000)
                need(manifest['prototype_clause_analysis.py']['sha256'] == assembler_sha
                     and sum(pin['bytes'] for pin in manifest.values()) <= 8_000_000)
                proof_root = third_root / 'clause-proof'
                values = {name: document(proof_root / name) for name in sorted(json_names)}
                for name in json_names:
                    raw = observed[(proof_root / name).relative_to(job).as_posix()]
                    need(len(raw) == manifest[name]['bytes'] and hashlib.sha256(raw).hexdigest() == manifest[name]['sha256'])
                analysis_role = descriptor['analysis_role']
                need(type(analysis_role) is dict and set(analysis_role) == {'workflow_id', 'model', 'graph_sha256'}
                     and type(analysis_role['workflow_id']) is str and re.fullmatch(r'[A-Fa-f0-9]{16,64}', analysis_role['workflow_id'])
                     and analysis_role['model'] == roles['mapper']['model'] and sha(analysis_role['graph_sha256'])
                     and len({row['workflow_id'].upper() for row in (analysis_role, roles['mapper'], roles['reviewer'])}) == 3)
                compact = {'schema_version': 1, 'scope': 'fox-forms-clause-analysis-v1-request', 'clauses': []}
                for attribute in ('WhereClause', 'OrderByClause'):
                    required_unit = next(row for row in required if row['source_attribute'] == attribute)
                    unit = unit_metadata[required_unit['unit_id']]
                    chunk = selected_units[unit['id']]
                    source = next(entry['source'] for entry in packet['sources']
                                  if any(row['id'] == unit['id'] for row in entry['facts']['code_units']))
                    compact['clauses'].append({'source_attribute': attribute, 'text': chunk['text'], 'unit': unit,
                                              'owner': all_objects[unit['owner_id']], 'source': source})
                same(values['clause-request.json'], compact)
                analysis_target = json.loads(canonical(target))
                analysis_target['opaf']['roles']['mapper'] = analysis_role
                analysis, analysis_room = role_output(proof_root / 'analysis', 'mapper', compact, analysis_target)
                need(set(analysis) == {'schema_version', 'scope', 'analyses'} and type(analysis['schema_version']) is int
                     and analysis['schema_version'] == 1 and analysis['scope'] == 'fox-forms-clause-analysis-v1'
                     and type(analysis['analyses']) is list and len(analysis['analyses']) == 2
                     and {row['source_attribute'] for row in analysis['analyses']} == {'WhereClause', 'OrderByClause'})
                for row in analysis['analyses']:
                    need(set(row) == {'source_attribute', 'intent', 'status', 'limitations'}
                         and row['status'] in ('proposal', 'unresolved') and type(row['limitations']) is list
                         and len(row['limitations']) <= 4 and (row['status'] != 'unresolved' or row['limitations']))
                    text(row['intent'], 512)
                    for limitation in row['limitations']: text(limitation, 1000)
                derived, assembly = values['derived-candidate.json'], values['derived-assembly.json']
                shape(derived, repair_request, {row['id'] for row in repair_request['owned_objects']})
                need(descriptor['candidate_sha256'] == hashed(derived) and type(assembly['changes']) is list
                     and len(assembly['changes']) == 2)
                expected_derived = json.loads(canonical(historical))
                changed_attributes = []
                for change, item in zip(assembly['changes'], compact['clauses']):
                    need(set(change) == {'source_attribute', 'unit_id', 'unit_sha256', 'claim_index', 'before',
                        'after', 'analysis', 'added_action', 'added_questions'} and type(change['claim_index']) is int)
                    unit = item['unit']; attribute = item['source_attribute']; changed_attributes.append(attribute)
                    interpreted = next(row for row in analysis['analyses'] if row['source_attribute'] == attribute)
                    index = change['claim_index']
                    same({key: change[key] for key in ('source_attribute', 'unit_id', 'unit_sha256', 'before', 'analysis')},
                        {'source_attribute': attribute, 'unit_id': unit['id'], 'unit_sha256': unit['sha256'],
                         'before': historical['blueprint']['claims'][index], 'analysis': interpreted})
                    need(change['before']['id'] == next(row['defective_claim_id'] for row in required
                         if row['source_attribute'] == attribute))
                    same(change['after'], {'id': change['before']['id'], 'source_object_id': unit['owner_id'],
                        'kind': 'behavior.intent', 'value': interpreted['intent'], 'status': interpreted['status'],
                        'evidence_refs': [unit['id']], 'reason': 'Derived model interpretation of ' + attribute +
                        '; not a source fact. Independent source-grounded review required.'})
                    action = change['added_action']
                    need(set(action) == {'id', 'claim_ids'} and action['claim_ids'] == [change['after']['id']])
                    identifier(action['id'])
                    need(type(change['added_questions']) is list and len(change['added_questions']) == len(interpreted['limitations']))
                    for question, limitation in zip(change['added_questions'], interpreted['limitations']):
                        need(set(question) == {'id', 'source_object_id', 'text'}
                             and question['source_object_id'] == unit['owner_id'] and question['text'] == limitation)
                        identifier(question['id'])
                    expected_derived['blueprint']['claims'][index] = change['after']
                    expected_derived['blueprint']['actions'].append(action)
                    expected_derived['blueprint']['questions'].extend(change['added_questions'])
                same(derived, expected_derived)
                same(assembly, {'schema_version': 1, 'scope': 'fox-forms-clause-analysis-v1-derived-assembly',
                    'assembler_version': 1, 'source_binding': selected['source_binding'],
                    'focus_request_sha256': hashed(repair_request), 'analysis_request_sha256': hashed(compact),
                    'analysis_response_sha256': hashed(analysis), 'original_candidate_sha256': hashed(historical),
                    'derived_candidate_sha256': hashed(derived), 'changes': assembly['changes'],
                    'repair_check': gate(derived, repair_request, 0), 'source_fact_check': gate(derived, repair_request, 0),
                    'raw_model_output': False, 'independent_review_required': True,
                    'generation_ready': False, 'business_behavior_accepted': False})
                analysis_invocation = values['analysis/mapper.json']['invocation']
                assembly_binding = {'schema_version': 1, 'scope': 'fox-clause-diagnostic-invocation-assembly-v1',
                    'analysis_checkpoint_sha256': manifest['analysis/mapper.json']['sha256'],
                    'analysis_invocation_sha256': hashed(analysis_invocation), 'assembly_sha256': hashed(assembly),
                    'candidate_sha256': hashed(derived), 'analysis_request_sha256': hashed(compact),
                    'source_binding': selected['source_binding'], 'raw_model_output': False}
                same(values['assembly-binding.json'], assembly_binding)
                review_payload = {'request': repair_request, 'candidate': derived, 'candidate_sha256': hashed(derived),
                    'review_context': {'schema_version': 1, 'scope': 'fox-dedicated-clause-derived-review-v1',
                        'trusted_requirements': {'compare_each_literal_clause_with_its_intent_and_limitations': True,
                            'reject_missing_conditions_ordering_or_invented_external_meaning': True,
                            'original_false_facts_are_historical_not_authority': True,
                            'require_both_clauses_and_action_references': True,
                            'assembly_is_derived_not_a_raw_blueprint_model_response': True,
                            'do_not_execute_or_accept_business_behavior': True},
                        'original_candidate': historical, 'clause_request': compact, 'raw_clause_analyses': analysis,
                        'assembly': assembly, 'assembly_binding': assembly_binding}}
                approved, clause_review_room = role_output(proof_root / 'review', 'reviewer', review_payload)
                need(len(rooms | {room, analysis_room, clause_review_room}) == len(rooms) + 3)
                same(approved, {'source_binding': selected['source_binding'], 'focus_binding': repair_request['focus_binding'],
                    'candidate_sha256': hashed(derived), 'verdict': 'APPROVED', 'findings': []})
                same(values['review-receipt.json'], review_receipt(derived, repair_request, 'APPROVED'))
                basis = values['diagnostic-intent.json']['approval_basis']; text(basis)
                summary = {'scope': 'one-source-bound-clause-analysis-diagnostic-not-conversion', 'job_id': run['id'],
                    'maximum_analysis_calls': 1, 'maximum_review_calls': 1, 'automatic_retry': False,
                    'source_binding': selected['source_binding'], 'focus_request_sha256': hashed(repair_request),
                    'original_candidate_sha256': hashed(historical), 'analysis_request_sha256': hashed(compact),
                    'module_sha256': assembler_sha, 'original_target_sha256': hashed(target),
                    'analysis_target_sha256': hashed(analysis_target), 'clause_count': 2,
                    'whole_clause_bytes': [item['unit']['bytes'] for item in compact['clauses']],
                    'production_profile_activated': False, 'production_run_resumed': False, 'apex_imported': False,
                    'approval_basis': basis}
                same(values['diagnostic-intent.json'], summary)
                unchanged = values['result.json']['original_job_files_unchanged']
                need(type(unchanged) is int and 0 < unchanged <= 100000)
                same(values['result.json'], {**summary, 'status': 'CLAUSE_DIAGNOSTIC_COMPLETED',
                    'analysis_room_id': analysis_room, 'analysis_output_sha256': hashed(analysis),
                    'derived_candidate_sha256': hashed(derived),
                    'analysis_statuses': {row['source_attribute']: row['status'] for row in analysis['analyses']},
                    'review_room_id': clause_review_room, 'review_verdict': 'APPROVED', 'approved_structured_design': True,
                    'finding_count': 0, 'finding_codes': [], 'original_job_files_unchanged': unchanged,
                    'business_behavior_accepted': False, 'diagnostic_not_production_continuation': True})
                third_policy = {**policy, 'clause_proof': 'retained-clause-diagnostic-v1',
                    'new_clause_analysis_calls': 0, 'repeated_clause_review_calls': 0,
                    'corrective_projection_review_calls': 1}
                third_plan = {**plan, 'source_checked_focuses': 7, 'planned_corrective_operations': ['projection_review'],
                    'new_clause_analysis_calls': 0, 'repeated_clause_review_calls': 0,
                    'corrective_projection_review_calls': 1, 'clause_proof_sha256': hashed(descriptor),
                    'analysis_role': descriptor['analysis_role']}
                third = document(job / 'mapping-epochs/epoch-000003.json')
                same(third, {**epoch, 'epoch_number': 3, 'strategy': 'retained-clause-diagnostic-v1',
                    'predecessor_sha256': hashed(epoch), 'approved_at': third['approved_at'],
                    'before_files': baseline_three, 'plan': third_plan, 'normalization_policy': third_policy,
                    'clause_proof_sha256': hashed(descriptor),
                    'checkpoint_sha256': hashed({'epoch_number': 3, 'predecessor_sha256': hashed(epoch),
                        'before_files': baseline_three, 'plan': third_plan, 'normalization_policy': third_policy})})
                need(type(third['epoch_number']) is int and type(third['approved_at']) in (int, float)
                     and math.isfinite(third['approved_at']) and third['approved_at'] > epoch['approved_at'])
                expected_events = {epoch_two_event,
                    (owner[0], run['id'] + ':epoch:000003:' + hashed(third), third['approved_at'])}
                need(expected_events <= {tuple(row) for row in events} if partition_family
                     else {tuple(row) for row in events} == expected_events)
                same(document(third_root / 'epoch-record.json'), third)
                same(document(third_root / 'predecessor-record.json'), epoch)
                derived_proof = {'focus_id': repair_request['focus_id'], 'kind': 'DERIVED_CLAUSE_DIAGNOSTIC',
                    'candidate_sha256': hashed(derived), 'source_fact_check': gate(derived, repair_request, 0),
                    'active_directory': 'epochs/epoch-000003/clause-proof', 'clause_proof_sha256': hashed(descriptor),
                    'analysis_invocation': analysis_invocation, 'reviewer_invocation': values['review/reviewer.json']['invocation'],
                    'review_request_sha256': hashed(review_payload), 'assembly_binding': assembly_binding,
                    'file_manifest_sha256': hashed(manifest)}
                projected = json.loads(canonical(candidate)); blueprint = projected['blueprint']
                owned_ids = {obj['id'] for obj in projection_request['owned_objects']}
                extras = [row for row in blueprint['objects'] if row['source_object_id'] not in owned_ids]
                need(len(extras) == 1)
                shared = extras[0]
                prior_objects = [row for row in derived['blueprint']['objects'] if row['source_object_id'] == shared['source_object_id']]
                need(len(prior_objects) == 1)
                same({key: value for key, value in shared.items() if key != 'reason'},
                     {key: value for key, value in prior_objects[0].items() if key != 'reason'})
                excluded_screens = [row for row in blueprint['screens'] if row['id'] == shared['screen_id']]
                same(excluded_screens, [row for row in derived['blueprint']['screens'] if row['id'] == shared['screen_id']])
                excluded_claims = [row for row in blueprint['claims'] if row['source_object_id'] not in owned_ids]
                need(len(excluded_claims) == 1 and not any(excluded_claims[0]['id'] in row['claim_ids']
                    for value in [candidate, *prefix[:6], derived] for category in ('actions', 'relationships')
                    for row in value['blueprint'][category]))
                blueprint['objects'] = [row for row in blueprint['objects'] if row['source_object_id'] in owned_ids]
                blueprint['screens'] = [row for row in blueprint['screens'] if row['id'] != shared['screen_id']]
                blueprint['claims'] = [row for row in blueprint['claims'] if row['source_object_id'] in owned_ids]
                aliases = []
                for row in blueprint['claims']:
                    if row['kind'] == 'object.item_type' and row['status'] == 'source_fact':
                        before = json.loads(canonical(row)); row['kind'] = 'item.item_type'
                        aliases.append({'before': before, 'after': json.loads(canonical(row))})
                need(len(aliases) == 2); shape(projected, projection_request, owned_ids)
                projection = {'schema_version': 1, 'scope': 'fox-focus-context-projection-v1',
                    'strategy': 'repair-source-facts-and-project-context-v1', 'source_binding': selected['source_binding'],
                    'request_sha256': hashed(projection_request), 'raw_candidate_sha256': hashed(candidate),
                    'candidate_sha256': hashed(projected), 'prior_active_proof_sha256': hashed(derived_proof),
                    'excluded_objects': extras, 'prior_objects': prior_objects, 'excluded_screens': excluded_screens,
                    'excluded_claims': excluded_claims, 'aliases': aliases, 'rationale_semantic_equivalence_asserted': False,
                    'source_fact_check': gate(projected, projection_request, 2)}
                shared = projection['excluded_objects'][0]
                need(projected['blueprint']['screens'] == [] and len(projected['blueprint']['objects']) == 32
                     and all(row['disposition'] == 'proposed' and row.get('screen_id') == shared['screen_id']
                         and all_objects[row['source_object_id']]['block_id'] == shared['source_object_id']
                         and all_objects[row['source_object_id']]['kind'] in ('Item', 'Trigger')
                         for row in projected['blueprint']['objects']))
                evidence = {'projection': projection, 'prior_active_proof': derived_proof}
                directory = third_root / projection_request['focus_id']
                same(document(directory / 'projection-candidate.json'), projected)
                same(document(directory / 'projection-receipt.json'), evidence)
                payload = {'request': projection_request, 'candidate': projected, 'candidate_sha256': hashed(projected),
                    'review_context': {'schema_version': 1, 'scope': 'fox-focus-extended-review-v1',
                        'operation': 'projection_review', 'raw_candidate': candidate, 'raw_candidate_sha256': hashed(candidate),
                        'evidence': evidence, 'trusted_requirements': {
                            'source_fact_values_and_every_ref_must_match_exact_whitelist': True,
                            'old_ai_approval_is_not_source_validation': True,
                            'review_every_required_clause_body_conditions_effects_and_action_refs': True,
                            'generic_or_relabelled_unsupported_facts_must_be_changes_required': True,
                            'compare_both_rationales_no_semantic_equivalence_from_machine_match': True,
                            'external_semantics_must_remain_uncertain': True,
                            'never_repair_candidate_or_accept_business_behavior': True}}}
                same(document(directory / 'reviewer-request.json'), payload)
                rejection, review_room = role_output(directory, 'reviewer', payload)
                need(review_room not in rooms | {room, analysis_room, clause_review_room}
                     and set(rejection) == {'source_binding', 'focus_binding', 'candidate_sha256', 'verdict', 'findings'}
                     and rejection['source_binding'] == selected['source_binding']
                     and rejection['focus_binding'] == projection_request['focus_binding']
                     and rejection['candidate_sha256'] == hashed(projected) and rejection['verdict'] == 'CHANGES_REQUIRED'
                     and type(rejection['findings']) is list and [finding['code'] for finding in rejection['findings']] ==
                         ['MISSING_SCREEN_DECLARATION', 'INVALID_OBJECT_SCREEN_REF']
                     and all(finding['source_object_id'] is None for finding in rejection['findings']))
                for finding in rejection['findings']:
                    need(set(finding) == {'source_object_id', 'code', 'detail'}); text(finding['detail'])
                receipt = review_receipt(projected, projection_request, 'CHANGES_REQUIRED')
                same(document(directory / 'review-receipt.json'), receipt)
                same(document(third_root / 'source-facts' / (projection_request['focus_id'] + '.json')),
                     gate(projected, projection_request, 2))
                archived_result = 'prototype-result-publications/epoch-000004/previous-result.json'
                result = document(job / archived_result if partition_family else job / 'prototype-result.json')
                checkpoint = result['artifacts']['checkpoint_directory']
                need(type(checkpoint) is str and 0 < len(checkpoint) <= 1024)
                portable = checkpoint.replace('\\', '/')
                need(re.match(r'(?:/|[A-Za-z]:/)', portable) and '//' not in portable
                     and all(part not in ('.', '..') for part in portable.split('/'))
                     and portable.endswith('/jobs/' + run['id'] + '/prototype-pipeline'))
                # This retained display path is never opened or used as authority.
                same(result, {'schema_version': 1, 'scope': 'fox-prototype-pipeline-v1',
                    'job_id': run['id'], 'source_binding': selected['source_binding'],
                    'status': 'CHANGES_REQUIRED', 'stage': 'reviewing', 'blocked_focus_id': projection_request['focus_id'],
                    'assessment': assessment, 'artifacts': {'checkpoint_directory': checkpoint},
                    'facts': {key: False for key in ('native_source_rendered', 'sqlcl_validated', 'schema_prepared',
                        'import_verified', 'runtime_verified', 'native_apex_generated', 'package_reimport_passed',
                        'clean_schema_install_passed', 'technically_verified', 'business_behavior_accepted', 'download_ready')}})
                need(type(result['schema_version']) is int)
                same(document(job / 'prototype-results' / (hashed(result) + '.json')), result)
                epoch_directories |= third_dirs
                if partition_family:
                    # Admission-only structural chain. No semantic module import,
                    # current-head dispatch, outside-job proof or execution grant.
                    context_sha = 'b48195fc859f52a7786e999350af3c7ec96c737d516caef906ea093347d2498c'
                    context_false = {key: False for key in ('authority_granted', 'processing_consent_verified',
                        'historical_review_provenance_verified', 'full_application_validated', 'generation_ready',
                        'native_apex_generated', 'import_verified', 'business_behavior_accepted')}
                    old_result = result
                    old_result_raw = observed[archived_result]
                    baseline_four = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()
                                     if name != archived_result}
                    baseline_four['prototype-result.json'] = hashlib.sha256(old_result_raw).hexdigest()
                    fourth_prefix = 'prototype-pipeline/epochs/epoch-000004'
                    fourth_root = job / fourth_prefix
                    fourth_dirs = {fourth_prefix, fourth_prefix + '/source-facts', fourth_prefix + '/container-proof',
                        fourth_prefix + '/container-proof/review', fourth_prefix + '/' + projection_request['focus_id'],
                        'prototype-result-publications', 'prototype-result-publications/epoch-000004'}
                    for name in sorted(fourth_dirs, key=lambda value: (value.count('/'), value)):
                        need((job / name).is_dir()); protected(job / name)
                    root_names = {'container-proposal.json', 'derived-root-candidate.json', 'diagnostic-intent.json',
                        'original-files.json', 'prefix-check.json', 'result.json', 'review-receipt.json', 'review-request.json',
                        'review/reviewer-intent.json', 'review/reviewer-target.json', 'review/reviewer.json'}
                    root_descriptor = document(fourth_root / 'container-proof-descriptor.json')
                    root_manifest = root_descriptor['original_manifest']
                    need(type(root_manifest) is dict and set(root_manifest) == root_names | {'prototype_design_context.py'}
                         and hashed(root_manifest) == root_descriptor['original_manifest_sha256'])
                    for pin in root_manifest.values():
                        need(type(pin) is dict and set(pin) == {'sha256', 'bytes'} and sha(pin['sha256'])
                             and type(pin['bytes']) is int and 0 < pin['bytes'] <= 2_000_000)
                    need(sum(pin['bytes'] for pin in root_manifest.values()) <= 8_000_000
                         and root_manifest['prototype_design_context.py']['sha256'] == context_sha)
                    root_proof = fourth_root / 'container-proof'
                    root_values = {name: document(root_proof / name) for name in sorted(root_names)}
                    for name in root_names:
                        raw = observed[(root_proof / name).relative_to(job).as_posix()]
                        need(len(raw) == root_manifest[name]['bytes']
                             and hashlib.sha256(raw).hexdigest() == root_manifest[name]['sha256'])
                    root_request, root_original = requests[0][0], prefix[0]
                    modules = [obj for obj in root_request['owned_objects'] if obj['kind'] == 'FormModule'
                               and obj['parent_id'] is None and obj['module_id'] == obj['id']]
                    need(len(modules) == 1)
                    module = modules[0]
                    need(not any(unit['owner_id'] == module['id'] for unit in unit_metadata.values()))
                    root_candidate = json.loads(canonical(root_original))
                    module_index = next(i for i, row in enumerate(root_candidate['blueprint']['objects'])
                                        if row['source_object_id'] == module['id'])
                    before = root_candidate['blueprint']['objects'][module_index]
                    need(set(before) == {'source_object_id', 'disposition', 'reason'} and before['disposition'] == 'omitted'
                         and before['reason'] == 'ordinary legacy visual container; web-recomposition')
                    after = {**before, 'disposition': 'unresolved', 'reason':
                        'Retain the source FormModule as nonvisual container metadata; descendant mappings '
                        'require separate context validation and independent review. No executable behavior '
                        'or whole-form omission is asserted.'}
                    root_candidate['blueprint']['objects'][module_index] = after
                    shape(root_candidate, root_request, {obj['id'] for obj in root_request['owned_objects']})
                    proposal = {'schema_version': 1, 'scope': 'fox-form-container-retention-proposal-v1',
                        'source_binding': selected['source_binding'], 'focus_id': root_request['focus_id'],
                        'focus_request_sha256': hashed(root_request), 'module_id': module['id'],
                        'object_index': module_index, 'source_object': module, 'original_candidate_sha256': hashed(root_original),
                        'candidate_sha256': hashed(root_candidate), 'before': before, 'after': after,
                        'raw_model_output': False, 'proposal_status': 'UNREVIEWED', 'independent_review_required': True,
                        'semantic_equivalence_asserted': False, **context_false}
                    same(root_values['container-proposal.json'], proposal)
                    same(root_values['derived-root-candidate.json'], root_candidate)
                    same(root_values['original-files.json'], baseline_four)
                    same(root_descriptor, {'schema_version': 1, 'scope': 'fox-prototype-container-proof-staging-v1',
                        'job_id': run['id'], 'project_id': run['project'], 'owner': owner[0],
                        'snapshot_sha256': hashlib.sha256(observed['source-snapshot.json']).hexdigest(),
                        'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                        'original_target_sha256': selected['target_profile_sha256'], 'predecessor_sha256': hashed(third),
                        'module_id': module['id'], 'context_module_sha256': context_sha, 'original_manifest': root_manifest,
                        'original_manifest_sha256': hashed(root_manifest), 'original_files': baseline_four,
                        'original_files_sha256': hashed(baseline_four), 'original_candidate_sha256': hashed(root_original),
                        'candidate_sha256': hashed(root_candidate)})
                    # Original normal-prefix proofs are rebuilt from already checked
                    # immutable role records; none is minted as new model output.
                    old_proofs = []
                    for (req, original_dir), value in zip(requests[:6], prefix[:6]):
                        mapped = document(original_dir / 'mapper.json')
                        reviewed = document(original_dir / 'reviewer.json')
                        old_proofs.append({'focus_id': req['focus_id'], 'candidate_sha256': hashed(value),
                            'source_fact_check': gate(value, req, 0),
                            'review_request_sha256': hashed({'request': req, 'candidate': value, 'candidate_sha256': hashed(value)}),
                            'review_sha256': hashed(reviewed['output']),
                            'review_receipt_sha256': hashed(review_receipt(value, req, 'APPROVED')),
                            'active_directory': original_dir.name, 'mapper_invocation': mapped['invocation'],
                            'reviewer_invocation': reviewed['invocation'], 'technical_evidence_sha256': None})
                    old_proofs.append(derived_proof)
                    candidates_four = [root_candidate, *prefix[1:6], derived, projected]

                    def context_data(proofs, proposal_root=False, *, context_requests=None,
                                     candidates=None, current_request=None, current_candidate=None,
                                     all_reviewed=False):
                        # Reconstruct the immutable context FORMAT only, not semantic
                        # approval or a new source-authenticity/consent attestation.
                        context_requests = [req for req, _ in requests] if context_requests is None else context_requests
                        candidates = candidates_four if candidates is None else candidates
                        current_request = projection_request if current_request is None else current_request
                        current_candidate = projected if current_candidate is None else current_candidate
                        ids = [req['focus_id'] for req in context_requests]
                        owner_of = {obj['id']: req['focus_id'] for req in context_requests for obj in req['owned_objects']}
                        mappings = {row['source_object_id']: row for value in candidates for row in value['blueprint']['objects']}
                        bindings = {}
                        reference_count = len(candidates) if all_reviewed else len(candidates) - 1
                        need(len(proofs) >= reference_count)
                        for req, value, proof in zip(context_requests[:reference_count], candidates[:reference_count], proofs):
                            bindings[req['focus_id']] = {'kind': 'CALLER_PINNED_RETAINED_REFERENCE',
                                'scope': 'fox-active-design-proof-reference-v1', 'focus_id': req['focus_id'],
                                'source_binding': selected['source_binding'], 'focus_request_sha256': hashed(req),
                                'candidate_sha256': hashed(value), 'target_profile_sha256': selected['target_profile_sha256'],
                                'proof_sha256': hashed(proof)}
                        if proposal_root:
                            bindings[root_request['focus_id']] = {'kind': 'UNREVIEWED_CONTAINER_RETENTION_PROPOSAL',
                                'focus_id': root_request['focus_id'], 'candidate_sha256': hashed(root_candidate),
                                'proposal_receipt_sha256': hashed(proposal)}
                        current_id = None if all_reviewed else current_request['focus_id']
                        if not all_reviewed:
                            bindings[current_id] = {'kind': 'CURRENT_UNREVIEWED_CANDIDATE', 'focus_id': current_id,
                                                    'candidate_sha256': hashed(current_candidate)}
                        summary = {'schema_version': 1, 'scope': 'fox-design-prefix-context-v1',
                            'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
                            'target_profile_sha256': selected['target_profile_sha256'], 'focus_ids': ids,
                            'candidate_sha256': [hashed(value) for value in candidates], 'reference_bindings': bindings,
                            'structural_prefix_valid': True,
                            'unreviewed_container_proposal_focus_ids': [root_request['focus_id']] if proposal_root else [],
                            'current_unreviewed_focus_id': current_id, 'source_objects_checked': len(mappings),
                            'caller_must_verify_source_authenticity_and_review_provenance': True, **context_false}
                        rows = []
                        if all_reviewed:
                            return summary, rows
                        screens = {screen['id']: (screen, req['focus_id']) for req, value in zip(context_requests, candidates)
                                   for screen in value['blueprint']['screens']}
                        selected_current = {chunk['code_unit_id']: chunk for chunk in current_request['chunks']}
                        for mapping in current_candidate['blueprint']['objects']:
                            source = all_objects[mapping['source_object_id']]
                            ancestors, seen, parent = [], set(), source['parent_id']
                            while parent is not None:
                                need(parent not in seen and parent in mappings); seen.add(parent)
                                ancestor = all_objects[parent]; ancestor_mapping = mappings[parent]
                                need(ancestor_mapping['disposition'] != 'omitted' if ancestor['kind'] in ('Block', 'FormModule') else True)
                                ancestors.append({'source': ancestor, 'mapping': ancestor_mapping,
                                                  'owner_binding': bindings[owner_of[parent]]})
                                parent = ancestor['parent_id']
                            screen_context = None
                            if 'screen_id' in mapping:
                                declaration, screen_focus = screens[mapping['screen_id']]
                                owners = [obj for obj in mappings if all_objects[obj]['kind'] == 'Block'
                                          and mappings[obj].get('screen_id') == mapping['screen_id']
                                          and mappings[obj]['disposition'] == 'proposed']
                                need(len(owners) == 1 and source['block_id'] == owners[0])
                                block_id = owners[0]
                                screen_context = {'declaration': declaration, 'source_block': all_objects[block_id],
                                    'owner_mapping': mappings[block_id], 'owner_binding': bindings[screen_focus],
                                    'borrowed_from_prior_focus': screen_focus != current_id}
                            else:
                                need(post_correction_review_failure and source['kind'] == 'DataSourceColumn'
                                     and mapping['disposition'] == 'unresolved'
                                     and set(mapping) == {'source_object_id', 'disposition', 'reason'})
                            coverage = []
                            if source['kind'] == 'Trigger':
                                units = [unit for unit in unit_metadata.values() if unit['owner_id'] == source['id']]
                                need(units)
                                for unit in units:
                                    claims = [claim for claim in current_candidate['blueprint']['claims']
                                        if claim['source_object_id'] == source['id'] and claim['kind'] == 'behavior.intent'
                                        and claim['status'] in ('proposal', 'unresolved') and type(claim['value']) is str
                                        and claim['value'].strip() and unit['id'] in claim['evidence_refs']]
                                    actions = [action for action in current_candidate['blueprint']['actions']
                                               if any(claim['id'] in action['claim_ids'] for claim in claims)]
                                    need(claims and actions and unit['id'] in selected_current)
                                    coverage.append({'unit': unit, 'selected_chunk_sha256': selected_current[unit['id']]['sha256'],
                                        'claim_ids': [claim['id'] for claim in claims], 'action_ids': [action['id'] for action in actions]})
                            rows.append({'focus_id': current_id, 'source': source, 'mapping': mapping,
                                'owner_binding': bindings[current_id], 'ancestors': ancestors,
                                'screen_context': screen_context, 'unit_coverage': coverage})
                        return summary, rows

                    root_prefix, _ = context_data(old_proofs, proposal_root=True)
                    same(root_values['prefix-check.json'], root_prefix)
                    root_payload = {'request': root_request, 'candidate': root_candidate, 'candidate_sha256': hashed(root_candidate),
                        'review_context': {'schema_version': 1, 'scope': 'fox-unadopted-container-retention-review-v1',
                            'proposal': proposal, 'original_candidate': root_original, 'original_active_proof': old_proofs[0],
                            'proposed_prefix_structural_check': root_prefix, 'root_owned_code_units': [],
                            'production_active_root_remains_original': True, 'proposal_adopted': False,
                            'scope_notice': 'This is a derived technical proposal for nonvisual FormModule metadata, not a mapper response '
                            'or a change to business behavior. All other rows, code, claims and ordering are unchanged. '
                            'The proposed prefix is not adopted and is not full-application validation.'}}
                    same(root_values['review-request.json'], root_payload)
                    root_review, root_room = role_output(root_proof / 'review', 'reviewer', root_payload)
                    need(root_room not in rooms | {room, analysis_room, clause_review_room, review_room})
                    same(root_review, {'source_binding': selected['source_binding'], 'focus_binding': root_request['focus_binding'],
                        'candidate_sha256': hashed(root_candidate), 'verdict': 'APPROVED', 'findings': []})
                    root_receipt = review_receipt(root_candidate, root_request, 'APPROVED')
                    same(root_values['review-receipt.json'], root_receipt)
                    root_intent = {'schema_version': 1, 'scope': 'one-unadopted-root-proposal-review', 'job_id': run['id'],
                        'source_binding': selected['source_binding'], 'target_profile_sha256': selected['target_profile_sha256'],
                        'module_sha256': context_sha, 'original_candidate_sha256': hashed(root_original),
                        'candidate_sha256': hashed(root_candidate), 'proposal_sha256': hashed(proposal),
                        'review_request_sha256': hashed(root_payload), 'original_files_sha256': hashed(baseline_four),
                        'maximum_new_model_calls': 1, 'generation_calls': 0, 'focus8_calls': 0, 'automatic_retry': False,
                        'production_run_resumed': False, 'proposal_adopted': False}
                    same(root_values['diagnostic-intent.json'], root_intent)
                    same(root_values['result.json'], {**root_intent, 'status': 'ROOT_PROPOSAL_REVIEW_COMPLETED_UNADOPTED',
                        'review_verdict': 'APPROVED', 'approved_structured_design': True, 'review_room_id': root_room,
                        'review_output_sha256': hashed(root_review), 'finding_codes': [],
                        'original_job_files_unchanged': len(baseline_four), 'apex_imported': False, 'business_behavior_accepted': False})
                    pin = {'raw_sha256': hashlib.sha256(old_result_raw).hexdigest(), 'canonical_sha256': hashed(old_result),
                        'history_path': 'prototype-results/' + hashed(old_result) + '.json',
                        'history_raw_sha256': baseline_four['prototype-results/' + hashed(old_result) + '.json']}
                    fourth_policy = {**third_policy, 'container_proof': 'retained-container-review-context-v1',
                        'prefix_context': 'exact-active-prefix-v1', 'new_container_review_calls': 0,
                        'repeated_root_mapper_calls': 0, 'repeated_projection_mapper_calls': 0, 'corrective_projection_review_calls': 1}
                    fourth_plan = {**third_plan, 'planned_corrective_operations': ['projection_review'],
                        'container_proof_sha256': hashed(root_descriptor), 'container_corrections': 1,
                        'new_container_review_calls': 0, 'repeated_root_mapper_calls': 0,
                        'repeated_projection_mapper_calls': 0, 'corrective_projection_review_calls': 1, 'previous_result': pin}
                    fourth = document(job / 'mapping-epochs/epoch-000004.json')
                    expected_fourth = {key: value for key, value in third.items() if key != 'clause_proof_sha256'}
                    expected_fourth.update(epoch_number=4, strategy='retained-container-review-context-v1',
                        predecessor_sha256=hashed(third), approved_at=fourth['approved_at'], before_files=baseline_four,
                        plan=fourth_plan, normalization_policy=fourth_policy, container_proof_sha256=hashed(root_descriptor),
                        checkpoint_sha256=hashed({'epoch_number': 4, 'predecessor_sha256': hashed(third),
                            'before_files': baseline_four, 'plan': fourth_plan, 'normalization_policy': fourth_policy}))
                    need(type(fourth['epoch_number']) is int and type(fourth['approved_at']) in (int, float)
                         and math.isfinite(fourth['approved_at']) and fourth['approved_at'] > third['approved_at'])
                    same(fourth, expected_fourth)
                    expected_four_events = expected_events | {
                        (owner[0], run['id'] + ':epoch:000004:' + hashed(fourth), fourth['approved_at'])}
                    need(expected_four_events <= {tuple(row) for row in events} if screen_family
                         else {tuple(row) for row in events} == expected_four_events)
                    same(document(fourth_root / 'epoch-record.json'), fourth)
                    same(document(fourth_root / 'predecessor-record.json'), third)
                    root_active_proof = {'focus_id': root_request['focus_id'], 'kind': 'DERIVED_APPROVED_CONTAINER_PROPOSAL',
                        'candidate_sha256': hashed(root_candidate), 'source_fact_check': gate(root_candidate, root_request, 0),
                        'active_directory': 'epochs/epoch-000004/container-proof', 'container_proof_sha256': hashed(root_descriptor),
                        'reviewer_invocation': root_values['review/reviewer.json']['invocation'],
                        'review_request_sha256': hashed(root_payload), 'review_receipt_sha256': hashed(root_receipt),
                        'proposal_sha256': hashed(proposal), 'file_manifest_sha256': hashed(root_manifest)}
                    active_proofs = [root_active_proof, *old_proofs[1:]]
                    summary_four, owned_rows = context_data(active_proofs)
                    design_context = {'schema_version': 1, 'scope': 'fox-design-review-context-v1',
                        'focus_id': projection_request['focus_id'], 'source_binding': selected['source_binding'],
                        'target_profile_sha256': selected['target_profile_sha256'],
                        'focus_request_sha256': hashed(projection_request), 'candidate_sha256': hashed(projected),
                        'prefix_check': summary_four, 'owned_rows': owned_rows, 'review_required': True, **context_false}
                    need(len(canonical(design_context)) <= 500000)
                    old_review_checkpoint = document(directory / 'reviewer.json')
                    payload_four = {**payload, 'design_context': design_context, 'retained_rejection': {
                        'review': rejection, 'invocation': old_review_checkpoint['invocation'],
                        'checkpoint_sha256': hashed(old_review_checkpoint), 'candidate_unchanged': True}}
                    current_dir = fourth_root / projection_request['focus_id']
                    same(document(current_dir / 'projection-candidate.json'), projected)
                    same(document(current_dir / 'projection-receipt.json'), evidence)
                    same(document(current_dir / 'reviewer-request.json'), payload_four)
                    current_review, current_room = role_output(current_dir, 'reviewer', payload_four)
                    need(current_room not in rooms | {room, analysis_room, clause_review_room, review_room, root_room})
                    same(current_review, rejection)
                    same(document(current_dir / 'review-receipt.json'), receipt)
                    same(document(fourth_root / 'source-facts' / (projection_request['focus_id'] + '.json')),
                         gate(projected, projection_request, 2))
                    active_proofs.append({'focus_id': projection_request['focus_id'], 'candidate_sha256': hashed(projected),
                        'source_fact_check': gate(projected, projection_request, 2), 'review_request_sha256': hashed(payload_four),
                        'review_sha256': hashed(current_review), 'review_receipt_sha256': hashed(receipt),
                        'active_directory': 'epochs/epoch-000004/' + projection_request['focus_id'],
                        'mapper_invocation': document(requests[7][1] / 'mapper.json')['invocation'],
                        'reviewer_invocation': document(current_dir / 'reviewer.json')['invocation'],
                        'technical_evidence_sha256': hashed(evidence)})
                    latest = document(job / 'prototype-result.json')
                    same(latest, {**old_result, 'mapping_epoch_sha256': hashed(fourth)})
                    history_path = 'prototype-results/' + hashed(latest) + '.json'
                    same(document(job / history_path), latest)
                    need(observed[history_path] == observed['prototype-result.json'])
                    same(document(job / 'prototype-result-publications/epoch-000004/publication.json'), {
                        'schema_version': 1, 'scope': 'fox-prototype-epoch-result-publication-v1', 'job_id': run['id'],
                        'project_id': run['project'], 'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                        'epoch_sha256': hashed(fourth), 'container_proof_sha256': hashed(root_descriptor),
                        'result_sha256': hashed(latest), 'history_path': history_path, 'status': 'CHANGES_REQUIRED',
                        'stage': 'reviewing', 'active_proofs_sha256': hashed(active_proofs), 'stage_files': {}, 'previous_result': pin})
                    epoch_directories |= fourth_dirs
                    if screen_family:
                        # Fixed head-five pre-review stop only. These checks do not
                        # invoke the formatter/projector or issue reuse authority.
                        baseline_five = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()}
                        need(len(baseline_five) == 135)
                        fifth_prefix = 'prototype-pipeline/epochs/epoch-000005'
                        fifth_root = job / fifth_prefix
                        fifth_dirs = {fifth_prefix, fifth_prefix + '/partition-proof',
                            fifth_prefix + '/partition-proof/review', 'prototype-result-publications/epoch-000005'}
                        for name in sorted(fifth_dirs, key=lambda value: (value.count('/'), value)):
                            need((job / name).is_dir()); protected(job / name)
                        compact_names = {'diagnostic-intent.json', 'original-files.json', 'review-request.json',
                            'full-audit-context.json', 'review-receipt.json', 'result.json',
                            'review/reviewer-target.json', 'review/reviewer-intent.json', 'review/reviewer.json'}
                        fifth_descriptor = document(fifth_root / 'partition-proof-descriptor.json')
                        compact_manifest = fifth_descriptor['original_manifest']
                        need(type(compact_manifest) is dict and set(compact_manifest) == compact_names
                             and hashed(compact_manifest) == fifth_descriptor['original_manifest_sha256'])
                        for item in compact_manifest.values():
                            need(type(item) is dict and set(item) == {'sha256', 'bytes'} and sha(item['sha256'])
                                 and type(item['bytes']) is int and 0 < item['bytes'] <= 2_000_000)
                        need(sum(item['bytes'] for item in compact_manifest.values()) <= 8_000_000)
                        compact_root = fifth_root / 'partition-proof'
                        compact_values = {name: document(compact_root / name) for name in sorted(compact_names)}
                        for name in compact_names:
                            raw = observed[(compact_root / name).relative_to(job).as_posix()]
                            need(len(raw) == compact_manifest[name]['bytes']
                                 and hashlib.sha256(raw).hexdigest() == compact_manifest[name]['sha256'])
                        formatter_pin = 'b81ec2cdd463c2db5b35d3fa1846f779d5191d079e07b1da94e89ae087785f57'
                        fourth_checkpoint = document(current_dir / 'reviewer.json')
                        history_pins = {'request_sha256': hashed(payload_four), 'receipt_sha256': hashed(fourth_checkpoint),
                                        'output_sha256': hashed(current_review)}
                        task = compact_values['review-request.json']
                        guidance = task['task_guidance']
                        need(type(guidance) is str and hashlib.sha256(guidance.encode()).hexdigest() ==
                             'ad358584583a51a81f2984af008aa38b7caab67fa080a174f0f08e2cf46e712e')
                        same(compact_values['full-audit-context.json'], design_context)
                        # Lossless pinned FORMAT validation, not an imported semantic
                        # validator. Natural keyed references forbid aliases/extras.
                        compact = task['design_context']
                        need(set(compact) == {'schema_version', 'scope', 'header', 'tables', 'owned_rows'}
                             and type(compact['schema_version']) is int and compact['schema_version'] == 1
                             and compact['scope'] == 'fox-compact-design-review-context-v1'
                             and set(compact['tables']) == {'sources', 'mappings', 'screens', 'owner_bindings'}
                             and len(canonical(compact)) <= 500000)
                        tables, used = compact['tables'], {key: set() for key in compact['tables']}
                        def lookup(table, key):
                            need(type(key) is str and type(tables[table]) is dict and key in tables[table])
                            value = tables[table][key]; used[table].add(key)
                            natural = 'source_object_id' if table == 'mappings' else 'focus_id' if table == 'owner_bindings' else 'id'
                            need(value[natural] == key)
                            return value
                        def triple(value):
                            need(set(value) == {'source_ref', 'mapping_ref', 'owner_ref'})
                            return {'source': lookup('sources', value['source_ref']),
                                'mapping': lookup('mappings', value['mapping_ref']),
                                'owner_binding': lookup('owner_bindings', value['owner_ref'])}
                        full = json.loads(canonical(compact['header']))
                        full['prefix_check']['reference_bindings'] = {key: lookup('owner_bindings', ref)
                            for key, ref in full['prefix_check']['reference_bindings'].items()}
                        full['owned_rows'] = []
                        for row in compact['owned_rows']:
                            need(set(row) == {'focus_id', 'source_ref', 'mapping_ref', 'owner_ref', 'ancestors',
                                             'screen_context', 'unit_coverage'})
                            screen = row['screen_context']; screen_value = None
                            if screen is not None:
                                need(set(screen) == {'source_ref', 'mapping_ref', 'owner_ref', 'screen_ref', 'borrowed_from_prior_focus'})
                                expanded = triple({key: screen[key] for key in ('source_ref', 'mapping_ref', 'owner_ref')})
                                screen_value = {'declaration': lookup('screens', screen['screen_ref']),
                                    'source_block': expanded['source'], 'owner_mapping': expanded['mapping'],
                                    'owner_binding': expanded['owner_binding'],
                                    'borrowed_from_prior_focus': screen['borrowed_from_prior_focus']}
                            full['owned_rows'].append({'focus_id': row['focus_id'],
                                **triple({key: row[key] for key in ('source_ref', 'mapping_ref', 'owner_ref')}),
                                'ancestors': [triple(value) for value in row['ancestors']], 'screen_context': screen_value,
                                'unit_coverage': row['unit_coverage']})
                        need(all(set(tables[key]) == used[key] for key in tables))
                        same(full, design_context)
                        expected_task = {'schema_version': 1, 'scope': 'fox-partition-review-task-v1',
                            'request': projection_request, 'candidate': projected, 'candidate_sha256': hashed(projected),
                            'target_profile_sha256': selected['target_profile_sha256'], 'design_context_sha256': hashed(design_context),
                            'design_context': compact, 'task_guidance': guidance, 'independent_semantic_review_required': True,
                            'historical_allegations': {'status': 'PAST_ALLEGATIONS_FOR_FRESH_REASSESSMENT', **history_pins,
                                'target_profile_sha256': selected['target_profile_sha256'], 'candidate_sha256': hashed(projected),
                                'allegations': [{'source_object_id': finding['source_object_id'], 'code': finding['code'],
                                    'allegation': finding['detail']} for finding in current_review['findings']],
                                'historical_conclusion_is_not_current_evidence': True,
                                'caller_must_preserve_original_request_receipt_and_output': True},
                            **context_false, 'review_context': payload_four['review_context']}
                        expected_task['task_binding'] = hashed(expected_task)
                        same(task, expected_task)
                        need(len(json.dumps(task, ensure_ascii=False, allow_nan=False).encode()) <= 650000)
                        same(compact_values['original-files.json'], baseline_five)
                        same(fifth_descriptor, {'schema_version': 1, 'scope': 'fox-prototype-partition-proof-staging-v1',
                            'job_id': run['id'], 'project_id': run['project'], 'owner': owner[0],
                            'snapshot_sha256': hashlib.sha256(observed['source-snapshot.json']).hexdigest(),
                            'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                            'original_target_sha256': selected['target_profile_sha256'], 'predecessor_sha256': hashed(fourth),
                            'formatter_sha256': formatter_pin, 'original_manifest': compact_manifest,
                            'original_manifest_sha256': hashed(compact_manifest), 'original_files': baseline_five,
                            'original_files_sha256': hashed(baseline_five), 'candidate_sha256': hashed(projected),
                            'review_task_sha256': hashed(task), 'expected_history_pins': history_pins})
                        compact_review, compact_room = role_output(compact_root / 'review', 'reviewer', task)
                        need(compact_room not in rooms | {room, analysis_room, clause_review_room, review_room, root_room, current_room})
                        same(compact_review, {'source_binding': selected['source_binding'], 'focus_binding': projection_request['focus_binding'],
                            'candidate_sha256': hashed(projected), 'verdict': 'APPROVED', 'findings': []})
                        same(compact_values['review-receipt.json'], review_receipt(projected, projection_request, 'APPROVED'))
                        diagnostic = {'schema_version': 1, 'scope': 'one-unadopted-compact-partition-review',
                            'job_id': run['id'], 'source_binding': selected['source_binding'],
                            'target_profile_sha256': selected['target_profile_sha256'], 'module_sha256': formatter_pin,
                            'candidate_sha256': hashed(projected), 'original_request_sha256': hashed(payload_four),
                            'new_request_sha256': hashed(task), 'prior_review_receipt_sha256': hashed(fourth_checkpoint),
                            'original_files_sha256': hashed(baseline_five), 'maximum_new_model_calls': 1,
                            'generation_calls': 0, 'automatic_retry': False, 'production_run_resumed': False, 'proposal_adopted': False}
                        same(compact_values['diagnostic-intent.json'], diagnostic)
                        same(compact_values['result.json'], {**diagnostic, 'status': 'COMPACT_PARTITION_REVIEW_COMPLETED_UNADOPTED',
                            'structured_review_valid': True, 'review_verdict': 'APPROVED', 'review_approved': True,
                            'review_room_id': compact_room, 'review_output_sha256': hashed(compact_review), 'finding_codes': [],
                            'original_job_files_unchanged': len(baseline_five), 'apex_imported': False, 'business_behavior_accepted': False})
                        fifth_pin = {'raw_sha256': hashlib.sha256(observed['prototype-result.json']).hexdigest(),
                            'canonical_sha256': hashed(latest), 'history_path': history_path,
                            'history_raw_sha256': hashlib.sha256(observed[history_path]).hexdigest()}
                        fifth_policy = {**fourth_policy, 'partition_review': 'retained-compact-review-v1',
                            'corrective_projection_review_calls': 0, 'new_corrective_model_calls': 0,
                            'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0}
                        fifth_plan = {**fourth_plan, 'ai_approved_focuses': 8, 'source_checked_focuses': 8, 'source_fact_violations': 0,
                            'partition_proof_sha256': hashed(fifth_descriptor), 'reused_review_focuses': 1,
                            'new_corrective_model_calls': 0, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0,
                            'planned_corrective_operations': [], 'previous_result': fifth_pin}
                        fifth = document(job / 'mapping-epochs/epoch-000005.json')
                        expected_fifth = {key: value for key, value in fourth.items() if key != 'container_proof_sha256'}
                        expected_fifth.update(epoch_number=5, strategy='retained-compact-review-v1', predecessor_sha256=hashed(fourth),
                            approved_at=fifth['approved_at'], before_files=baseline_five, plan=fifth_plan, normalization_policy=fifth_policy,
                            partition_proof_sha256=hashed(fifth_descriptor), checkpoint_sha256=hashed({'epoch_number': 5,
                                'predecessor_sha256': hashed(fourth), 'before_files': baseline_five,
                                'plan': fifth_plan, 'normalization_policy': fifth_policy}))
                        need(type(fifth['epoch_number']) is int and type(fifth['approved_at']) in (int, float)
                             and math.isfinite(fifth['approved_at']) and fifth['approved_at'] > fourth['approved_at'])
                        same(fifth, expected_fifth)
                        expected_five_events = expected_four_events | {
                            (owner[0], run['id'] + ':epoch:000005:' + hashed(fifth), fifth['approved_at'])}
                        need(expected_five_events <= {tuple(row) for row in events} if review_scope_failure
                             else {tuple(row) for row in events} == expected_five_events)
                        same(document(fifth_root / 'epoch-record.json'), fifth)
                        same(document(fifth_root / 'predecessor-record.json'), fourth)
                        previous_five = 'prototype-result-publications/epoch-000005/previous-result.json'
                        same(document(job / previous_five), latest)
                        need(observed[previous_five] == observed['prototype-result.json'])
                        # Reconstruct exactly the next ordinary ownership-sized source
                        # partition. Any other/bisected/unknown stop remains blocking.
                        remaining = ordered[cursor:]
                        need(remaining and assessment['focus_count'] > 8)
                        first_nine = remaining[0]
                        group_nine = (first_nine['block_id'], first_nine['module_id'])
                        owned_nine = []
                        for obj in remaining:
                            if (obj['block_id'], obj['module_id']) != group_nine or len(owned_nine) == 32: break
                            owned_nine.append(obj)
                        need(owned_nine and all(obj['kind'] in ('Item', 'Trigger') for obj in owned_nine))
                        ids_nine = {obj['id'] for obj in owned_nine}
                        focus_nine = 'focus-' + hashed([selected['source_binding'], [obj['id'] for obj in owned_nine]])[:24]
                        dir_nine = fifth_root / focus_nine
                        need(dir_nine.is_dir()); protected(dir_nine)
                        request_nine = document(dir_nine / 'mapper-request.json', 500000)
                        entries = [entry for entry in packet['sources'] if ids_nine <= {obj['id'] for obj in entry['facts']['objects']}]
                        need(len(entries) == 1)
                        facts_nine = entries[0]['facts']
                        units_nine = [unit for obj in owned_nine for unit in facts_nine['code_units'] if unit['owner_id'] == obj['id']]
                        associated = ids_nine | {unit['id'] for unit in units_nine}
                        links_nine = [value for value in facts_nine['links'] if value['source_id'] in associated]
                        findings_nine = [value for value in facts_nine['findings'] if not value['object_ids'] or associated.intersection(value['object_ids'])]
                        contexts = set()
                        def ancestry(ref):
                            seen = set()
                            while ref is not None:
                                need(ref in all_objects and ref not in seen); seen.add(ref); contexts.add(ref)
                                ref = all_objects[ref]['parent_id']
                        for obj in owned_nine: ancestry(obj['parent_id'])
                        for link in links_nine:
                            if link['status'] == 'resolved': ancestry(link['target_id'])
                        for finding in findings_nine:
                            for ref in finding['object_ids']: ancestry(ref)
                        chunk_units = {value['code_unit_id']: value for value in chunks.values()}
                        supplied_nine = {value['code_unit_id']: value for value in request_nine['chunks']}
                        need(len(supplied_nine) == len(request_nine['chunks']))
                        chunks_nine = []
                        for unit in units_nine:
                            chunk = chunk_units[unit['id']]
                            if chunk['id'] in selected['approved_chunk_hashes']:
                                body = supplied_nine[unit['id']]['text']
                                need(type(body) is str and len(body.encode()) == unit['bytes']
                                     and hashlib.sha256(body.encode()).hexdigest() == unit['sha256'])
                                chunks_nine.append({**chunk, 'text': body})
                        object_order = {ref: index for index, ref in enumerate(all_objects)}
                        expected_request = {'schema_version': 1, 'scope': 'fox-forms-focus-request-v1',
                            'source_binding': selected['source_binding'], 'focus_id': focus_nine, 'source_index': source_index,
                            'owned_objects': owned_nine, 'context_objects': [all_objects[ref] for ref in sorted(contexts - ids_nine, key=object_order.__getitem__)],
                            'code_units': units_nine, 'links': links_nine,
                            'dependencies': [value for value in facts_nine['dependencies'] if value['source_id'] in associated],
                            'findings': findings_nine, 'chunks': chunks_nine,
                            'unselected_code_unit_ids': [unit['id'] for unit in units_nine if chunk_units[unit['id']]['id'] not in selected['approved_chunk_hashes']],
                            'safety': requests[0][0]['safety']}
                        expected_request['focus_binding'] = hashed(expected_request)
                        same(request_nine, expected_request)
                        raw_nine, mapper_nine_room = role_output(dir_nine, 'mapper', request_nine)
                        need(mapper_nine_room not in rooms | {room, analysis_room, clause_review_room, review_room, root_room, current_room, compact_room})
                        shape(raw_nine, request_nine, ids_nine)
                        blueprint_nine = raw_nine['blueprint']
                        need(len(blueprint_nine['screens']) == 1)
                        duplicate = blueprint_nine['screens'][0]
                        prior_screens = [(screen, value) for value in candidates_four for screen in value['blueprint']['screens']
                                         if screen['id'] == duplicate['id']]
                        need(len(prior_screens) == 1); same(duplicate, prior_screens[0][0])
                        block_owners = [mapping for value in candidates_four for mapping in value['blueprint']['objects']
                            if all_objects[mapping['source_object_id']]['kind'] == 'Block' and mapping['disposition'] == 'proposed'
                            and mapping.get('screen_id') == duplicate['id']]
                        need(len(block_owners) == 1)
                        block_nine = block_owners[0]['source_object_id']
                        need(block_nine in {obj['id'] for obj in request_nine['context_objects']}
                             and duplicate['id'] == 'screen-' + block_nine and all(obj['block_id'] == block_nine for obj in owned_nine))
                        prior_mappings = {mapping['source_object_id']: mapping for value in candidates_four for mapping in value['blueprint']['objects']}
                        for mapping in blueprint_nine['objects']:
                            need(mapping['disposition'] == 'proposed' and mapping.get('screen_id') == duplicate['id'] and 'native_component' not in mapping)
                            source = all_objects[mapping['source_object_id']]; ancestry(source['parent_id'])
                            parent, seen = source['parent_id'], set()
                            while parent is not None:
                                need(parent not in seen); seen.add(parent)
                                ancestor = all_objects[parent]
                                if ancestor['kind'] in ('Block', 'FormModule'): need(prior_mappings[parent]['disposition'] != 'omitted')
                                parent = ancestor['parent_id']
                            need(block_nine in seen)
                        evidence_owners = {ref: ref for ref in all_objects}
                        evidence_owners.update({ref: value['owner_id'] for ref, value in unit_metadata.items()})
                        for entry in packet['sources']:
                            local_ids = {obj['id'] for obj in entry['facts']['objects']}
                            for category, collection, prefix_id in (('link', 'links', 'fflink1-'),
                                                                    ('dependency', 'dependencies', 'ffdep1-')):
                                for value in entry['facts'][collection]:
                                    # Same occurrence identity as evidence_reference_id;
                                    # these extractor rows deliberately have no id field.
                                    ref = prefix_id + hashed([entry['source']['sha256'], category, value])[:24]
                                    need(ref not in evidence_owners and value['source_id'] in local_ids)
                                    evidence_owners[ref] = value['source_id']
                        claims_nine = {claim['id']: claim for claim in blueprint_nine['claims']}
                        need(len(claims_nine) == len(blueprint_nine['claims']))
                        prior_ids = set(all_objects) | set(unit_metadata) | {value['id'] for candidate in candidates_four
                            for category in ('screens', 'claims', 'actions', 'relationships', 'questions', 'assumptions')
                            for value in candidate['blueprint'][category]}
                        seen_nine = set()
                        for category in ('claims', 'actions', 'relationships', 'questions', 'assumptions'):
                            for value in blueprint_nine[category]:
                                need(value['id'] not in prior_ids and value['id'] not in seen_nine)
                                seen_nine.add(value['id'])
                        for claim in claims_nine.values():
                            refs = claim['evidence_refs']
                            need(claim['status'] in ('proposal', 'unresolved') and refs and len(set(refs)) == len(refs)
                                 and all(ref in evidence_owners for ref in refs)
                                 and any(evidence_owners[ref] == claim['source_object_id'] for ref in refs))
                        for category in ('actions', 'relationships'):
                            for action in blueprint_nine[category]:
                                need(action['claim_ids'] and len(set(action['claim_ids'])) == len(action['claim_ids'])
                                     and set(action['claim_ids']) <= claims_nine.keys())
                        for obj in owned_nine:
                            if obj['kind'] != 'Trigger': continue
                            units = [unit for unit in units_nine if unit['owner_id'] == obj['id']]
                            need(units)
                            for unit in units:
                                covered = [claim['id'] for claim in claims_nine.values() if claim['source_object_id'] == obj['id']
                                    and claim['kind'] == 'behavior.intent' and type(claim['value']) is str and claim['value'].strip()
                                    and unit['id'] in claim['evidence_refs']]
                                need(unit['id'] in supplied_nine and covered and any(set(covered).intersection(action['claim_ids'])
                                     for action in blueprint_nine['actions']))
                        # No reviewer, derived candidate, source-fact receipt, later
                        # focus or fifth publication is silently added to closure.
                        need(len(observed) == 153)
                        epoch_directories |= fifth_dirs | {fifth_prefix + '/' + focus_nine}
                        if review_scope_failure:
                            # Exactly the unchanged epoch-six terminal review-scope
                            # defect. No current/future runtime helper is available
                            # in the measured deployment bridge's old namespace.
                            need(len(owned_nine) == 32 and len(units_nine) == 3
                                 and sum(obj['kind'] == 'Trigger' for obj in owned_nine) == 3)
                            baseline_six = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()}
                            sixth_prefix = 'prototype-pipeline/epochs/epoch-000006'
                            sixth_root = job / sixth_prefix
                            sixth_dir = sixth_root / focus_nine
                            sixth_dirs = {sixth_prefix, sixth_prefix + '/' + focus_nine,
                                'prototype-result-publications/epoch-000006'}
                            for name in sorted(sixth_dirs, key=lambda value: (value.count('/'), value)):
                                need((job / name).is_dir()); protected(job / name)

                            # Rebuild reference8 from the retained compact proof,
                            # not the historical rejected fourth review proof.
                            proof_eight = {'focus_id': projection_request['focus_id'],
                                'kind': 'RETAINED_COMPACT_PARTITION_REVIEW', 'candidate_sha256': hashed(projected),
                                'source_fact_check': gate(projected, projection_request, 2),
                                'active_directory': 'epochs/epoch-000005/partition-proof',
                                'partition_proof_sha256': hashed(fifth_descriptor),
                                'reviewer_invocation': compact_values['review/reviewer.json']['invocation'],
                                'review_request_sha256': hashed(task),
                                'review_receipt_sha256': hashed(compact_values['review-receipt.json']),
                                'review_sha256': hashed(compact_review), 'prior_review_request_sha256': hashed(payload_four),
                                'prior_review_checkpoint_sha256': hashed(fourth_checkpoint),
                                'full_audit_context_sha256': hashed(design_context), 'formatter_sha256': formatter_pin,
                                'file_manifest_sha256': hashed(compact_manifest)}
                            proofs_eight = [*active_proofs[:7], proof_eight]
                            summary_eight, _ = context_data(proofs_eight, all_reviewed=True)
                            refs_eight = {key: {field: value for field, value in ref.items() if field != 'kind'}
                                          for key, ref in summary_eight['reference_bindings'].items()}
                            candidate_nine = json.loads(canonical(raw_nine))
                            candidate_nine['blueprint']['screens'] = []
                            same(document(sixth_dir / 'screen-input-candidate.json'), raw_nine)
                            same(document(sixth_dir / 'projection-candidate.json'), candidate_nine)
                            summary_nine, rows_nine = context_data(proofs_eight,
                                context_requests=[req for req, _ in requests] + [request_nine],
                                candidates=[*candidates_four, candidate_nine], current_request=request_nine,
                                current_candidate=candidate_nine)
                            audit_nine = {'schema_version': 1, 'scope': 'fox-design-review-context-v1',
                                'focus_id': focus_nine, 'source_binding': selected['source_binding'],
                                'target_profile_sha256': selected['target_profile_sha256'],
                                'focus_request_sha256': hashed(request_nine), 'candidate_sha256': hashed(candidate_nine),
                                'prefix_check': summary_nine, 'owned_rows': rows_nine, 'review_required': True, **context_false}
                            same(document(sixth_dir / 'full-audit-context.json'), audit_nine)
                            need(len(canonical(audit_nine)) <= 500000)
                            block_focus = next(req['focus_id'] for req, _ in requests
                                               if block_nine in {obj['id'] for obj in req['owned_objects']})
                            screen_receipt = {'schema_version': 1, 'scope': 'fox-context-screen-projection-v1',
                                'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
                                'focus_id': focus_nine, 'focus_request_sha256': hashed(request_nine),
                                'target_profile_sha256': selected['target_profile_sha256'],
                                'raw_candidate_sha256': hashed(raw_nine), 'candidate_sha256': hashed(candidate_nine),
                                'status': 'PROJECTED_UNREVIEWED', 'removed_screens': [{
                                    'screen_index': 0, 'declaration': duplicate, 'source_block': all_objects[block_nine],
                                    'owner_mapping': block_owners[0], 'prior_focus_id': block_focus,
                                    'prior_reference': refs_eight[block_focus],
                                    'current_reference_source_ids': [row['source_object_id'] for row in blueprint_nine['objects']]}],
                                'prior_prefix_sha256': hashed(candidates_four), 'prior_references_sha256': hashed(refs_eight),
                                'prior_prefix_check_sha256': hashed(summary_eight),
                                'derived_review_context_sha256': hashed(audit_nine), 'only_screen_declarations_changed': True,
                                'raw_model_output': False, 'independent_review_required': True,
                                'semantic_equivalence_asserted': False, 'caller_must_reconstruct_prior_reviewed_views': True,
                                'caller_must_preserve_originals': True, 'ai_approval_granted': False, **context_false}
                            same(document(sixth_root / 'screen-projection-receipt.json'), screen_receipt)
                            same(document(sixth_dir / 'screen-projection-receipt.json'), screen_receipt)
                            screen_evidence = {'schema_version': 1, 'scope': 'fox-focus-context-screen-normalization-v1',
                                'base_technical_evidence': None, 'context_screen_projection': screen_receipt,
                                'raw_mapper_candidate_sha256': hashed(raw_nine)}
                            same(document(sixth_dir / 'projection-receipt.json'), screen_evidence)

                            # Build the canonical compact codec from independently
                            # reconstructed full context; no self-rehashed header,
                            # alias, unused/foreign table or changed guidance wins.
                            compact_tables = {key: {} for key in ('sources', 'mappings', 'screens', 'owner_bindings')}
                            def intern(table, key, value):
                                if key in compact_tables[table]: same(compact_tables[table][key], value)
                                else: compact_tables[table][key] = value
                                return key
                            def compact_triple(source, mapping, binding):
                                need(source['id'] == mapping['source_object_id'])
                                return {'source_ref': intern('sources', source['id'], source),
                                    'mapping_ref': intern('mappings', source['id'], mapping),
                                    'owner_ref': intern('owner_bindings', binding['focus_id'], binding)}
                            compact_header = json.loads(canonical({key: value for key, value in audit_nine.items() if key != 'owned_rows'}))
                            compact_header['prefix_check']['reference_bindings'] = {
                                key: intern('owner_bindings', value['focus_id'], value)
                                for key, value in compact_header['prefix_check']['reference_bindings'].items()}
                            compact_rows = []
                            for row in rows_nine:
                                screen = row['screen_context']
                                need(screen is not None and screen['borrowed_from_prior_focus'] is True
                                     and screen['source_block']['id'] == block_nine)
                                compact_rows.append({'focus_id': focus_nine,
                                    **compact_triple(row['source'], row['mapping'], row['owner_binding']),
                                    'ancestors': [compact_triple(a['source'], a['mapping'], a['owner_binding']) for a in row['ancestors']],
                                    'screen_context': {**compact_triple(screen['source_block'], screen['owner_mapping'], screen['owner_binding']),
                                        'screen_ref': intern('screens', screen['declaration']['id'], screen['declaration']),
                                        'borrowed_from_prior_focus': True}, 'unit_coverage': row['unit_coverage']})
                            task_nine = {'schema_version': 1, 'scope': 'fox-partition-review-task-v1',
                                'request': request_nine, 'candidate': candidate_nine, 'candidate_sha256': hashed(candidate_nine),
                                'target_profile_sha256': selected['target_profile_sha256'], 'design_context_sha256': hashed(audit_nine),
                                'design_context': {'schema_version': 1, 'scope': 'fox-compact-design-review-context-v1',
                                    'header': compact_header, 'tables': compact_tables, 'owned_rows': compact_rows},
                                'task_guidance': guidance, 'independent_semantic_review_required': True,
                                'historical_allegations': None, **context_false,
                                'review_context': {'raw_candidate': raw_nine, 'raw_candidate_sha256': hashed(raw_nine),
                                                   'evidence': screen_evidence}}
                            task_nine['task_binding'] = hashed(task_nine)
                            need(len(canonical(task_nine['design_context'])) <= 500000
                                 and len(json.dumps(task_nine, ensure_ascii=False, allow_nan=False).encode()) <= 650000)
                            same(document(sixth_dir / 'reviewer-request.json'), task_nine)
                            review_nine, reviewer_nine_room = role_output(sixth_dir, 'reviewer', task_nine)
                            need(reviewer_nine_room not in rooms | {room, analysis_room, clause_review_room, review_room,
                                 root_room, current_room, compact_room, mapper_nine_room})
                            need(set(review_nine) == {'source_binding', 'focus_binding', 'candidate_sha256', 'verdict', 'findings'}
                                 and review_nine['source_binding'] == selected['source_binding']
                                 and review_nine['focus_binding'] == request_nine['focus_binding']
                                 and review_nine['candidate_sha256'] == hashed(candidate_nine)
                                 and review_nine['verdict'] == 'CHANGES_REQUIRED'
                                 and type(review_nine['findings']) is list and len(review_nine['findings']) == 1
                                 and len(canonical(review_nine)) <= 100000)
                            for finding in review_nine['findings']:
                                need(type(finding) is dict and set(finding) == {'source_object_id', 'code', 'detail'}
                                     and finding['source_object_id'] == block_nine and block_nine not in ids_nine
                                     and all_objects[block_nine]['kind'] == 'Block'
                                     and finding['code'] == 'MISSING_SCREEN_DECLARATION')
                                text(finding['detail'])
                            # The output is intentionally invalid for the ordinary
                            # owner gate. It remains negative raw DATA, not a receipt.
                            sixth_pin = {'raw_sha256': hashlib.sha256(observed['prototype-result.json']).hexdigest(),
                                'canonical_sha256': hashed(latest), 'history_path': history_path,
                                'history_raw_sha256': hashlib.sha256(observed[history_path]).hexdigest()}
                            sixth_policy = {**fifth_policy, 'context_screen_projection': 'context-screen-projection-v1',
                                'projector_sha256': '67577835743872632bc14daaf0f168b58bd0d0ba3f515a7915f2d96357cca022',
                                'new_corrective_model_calls': 1, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0}
                            sixth_plan = {**fifth_plan, 'saved_mapping_focuses': 1, 'saved_mapping_source_checked': True,
                                'pending_review_focus_id': focus_nine, 'unstarted_focus_count': assessment['focus_count'] - 9,
                                'remaining_focus_count': assessment['focus_count'] - 8, 'projected_context_screens': 1,
                                'new_corrective_model_calls': 1, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0,
                                'planned_corrective_operations': ['review_saved_projection'],
                                'screen_projection_sha256': hashed(screen_receipt), 'previous_result': sixth_pin}
                            sixth = document(job / 'mapping-epochs/epoch-000006.json')
                            expected_sixth = {key: value for key, value in fifth.items() if key != 'partition_proof_sha256'}
                            expected_sixth.update(epoch_number=6, strategy='context-screen-projection-v1',
                                predecessor_sha256=hashed(fifth), approved_at=sixth['approved_at'], before_files=baseline_six,
                                plan=sixth_plan, normalization_policy=sixth_policy, screen_projection_sha256=hashed(screen_receipt),
                                checkpoint_sha256=hashed({'epoch_number': 6, 'predecessor_sha256': hashed(fifth),
                                    'before_files': baseline_six, 'plan': sixth_plan, 'normalization_policy': sixth_policy}))
                            need(type(sixth['epoch_number']) is int and type(sixth['approved_at']) in (int, float)
                                 and math.isfinite(sixth['approved_at']) and sixth['approved_at'] > fifth['approved_at'])
                            same(sixth, expected_sixth)
                            need({tuple(row) for row in events} == expected_five_events | {
                                (owner[0], run['id'] + ':epoch:000006:' + hashed(sixth), sixth['approved_at'])})
                            same(document(sixth_root / 'epoch-record.json'), sixth)
                            same(document(sixth_root / 'predecessor-record.json'), fifth)
                            previous_six = 'prototype-result-publications/epoch-000006/previous-result.json'
                            same(document(job / previous_six), latest)
                            need(observed[previous_six] == observed['prototype-result.json'] and len(observed) == 167)
                            epoch_directories |= sixth_dirs
                            if post_correction_review_failure:
                                # Fixed preservation-only successor of the167 stop.
                                # The archived-pointer leaf above rebuilds ONLY its
                                # historical checkpoint. Restore the actual latest
                                # leaf before the final publication/physical closure.
                                failed_before = {name: hashlib.sha256(raw).hexdigest() for name, raw in observed.items()}
                                correction_prefix = sixth_prefix + '/review-correction'
                                correction_root = job / correction_prefix
                                correction_dir = correction_root / 'attempt-000001'
                                for path in (correction_root, correction_dir, sixth_root / 'source-facts'):
                                    need(path.is_dir()); protected(path)
                                    epoch_directories.add(path.relative_to(job).as_posix())

                                def ledger(req, compact):
                                    inherited = []
                                    for row in compact['owned_rows']:
                                        screen = row['screen_context']
                                        if screen is not None and screen['borrowed_from_prior_focus']:
                                            value = {key: screen[key] for key in ('source_ref', 'mapping_ref', 'owner_ref', 'screen_ref')}
                                            value['declaration'] = compact['tables']['screens'][screen['screen_ref']]
                                            if value not in inherited: inherited.append(value)
                                    return {'owned_objects': [{'id': row['id'], 'kind': row['kind']} for row in req['owned_objects']],
                                        'context_only_objects': [{'id': row['id'], 'kind': row['kind']} for row in req['context_objects']],
                                        'inherited_screens': inherited,
                                        'rule': 'Only owned_objects may be finding source_object_id values. Context grants no ownership. '
                                            'Inherited screens need no local declaration without an owned Block. '
                                            'Use null for an application-level finding; genuine semantic defects still block.'}

                                pins = {'failed_request_sha256': hashlib.sha256(observed[sixth_prefix + '/' + focus_nine + '/reviewer-request.json']).hexdigest(),
                                    'failed_response_sha256': hashlib.sha256(observed[sixth_prefix + '/' + focus_nine + '/reviewer.json']).hexdigest(),
                                    'failed_task_sha256': hashed(task_nine), 'failed_output_sha256': hashed(review_nine),
                                    'failed_invocation_sha256': hashed(document(sixth_dir / 'reviewer.json')['invocation']),
                                    'kind': 'CONTEXT_ONLY_FINDING_ATTRIBUTION', 'non_owned_finding_ids': [block_nine]}
                                corrected_task = json.loads(canonical(task_nine))
                                corrected_task.update(scope='fox-prototype-review-scope-correction-v1',
                                    ownership_ledger=ledger(request_nine, task_nine['design_context']), correction_of=pins)
                                corrected_task['task_guidance'] += (' The explicit ownership_ledger is authoritative for section ownership. '
                                    'This is a new independent review of the unchanged candidate, not acceptance of the old response. '
                                    'The prior response was rejected structurally and is not a semantic review receipt. '
                                    'Do not force approval; identify any genuine defects in the owned mapping.')
                                corrected_task.pop('task_binding'); corrected_task['task_binding'] = hashed(corrected_task)
                                correction_plan = {**pins, 'pending_review_focus_id': focus_nine,
                                    'candidate_sha256': hashed(candidate_nine), 'design_context_sha256': hashed(audit_nine),
                                    'corrected_task_sha256': hashed(corrected_task), 'ownership_ledger_sha256': hashed(corrected_task['ownership_ledger']),
                                    'ai_approved_focuses': 8, 'saved_mapping_focuses': 1,
                                    'unstarted_focus_count': assessment['focus_count'] - 9,
                                    'remaining_focus_count': assessment['focus_count'] - 8, 'new_reviewer_calls': 1, 'repeated_mapper_calls': 0}
                                child = document(correction_root / 'authorization.json')
                                expected_child = {key: sixth[key] for key in ('job_id', 'project_id', 'snapshot_sha256',
                                    'source_hash', 'source_binding', 'target_profile_sha256', 'owner', 'approvals')}
                                expected_child.update(schema_version=1, scope='fox-prototype-review-scope-correction-v1',
                                    epoch_number=6, epoch_record_sha256=hashed(sixth), approved_at=child['approved_at'],
                                    before_files=failed_before, plan=correction_plan,
                                    checkpoint_sha256=hashed({'scope': 'fox-prototype-review-scope-correction-v1',
                                        'epoch_record_sha256': hashed(sixth), 'before_files': failed_before, 'plan': correction_plan}))
                                need(type(child['approved_at']) in (int, float) and math.isfinite(child['approved_at'])
                                     and child['approved_at'] > sixth['approved_at'])
                                same(child, expected_child)
                                correction_events = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
                                    '(object_id=? OR object_id LIKE ?)', ('approved_prototype_review_scope_correction',
                                    run['id'], run['id'] + ':%')).fetchall()
                                need([tuple(row) for row in correction_events] == [(owner[0],
                                    run['id'] + ':review-correction:000006:' + hashed(child), child['approved_at'])])
                                same(document(correction_dir / 'reviewer-request.json'), corrected_task)
                                corrected_review, corrected_room = role_output(correction_dir, 'reviewer', corrected_task)
                                used_rooms = rooms | {room, analysis_room, clause_review_room, review_room, root_room,
                                    current_room, compact_room, mapper_nine_room, reviewer_nine_room}
                                need(corrected_room not in used_rooms); used_rooms.add(corrected_room)
                                same(corrected_review, {'source_binding': selected['source_binding'], 'focus_binding': request_nine['focus_binding'],
                                    'candidate_sha256': hashed(candidate_nine), 'verdict': 'APPROVED', 'findings': []})
                                checked = review_receipt(candidate_nine, request_nine, 'APPROVED')
                                same(document(correction_dir / 'review-receipt.json'), checked)
                                facts_nine_count = sum(claim['status'] == 'source_fact' for claim in candidate_nine['blueprint']['claims'])
                                same(document(sixth_root / 'source-facts' / (focus_nine + '.json')), gate(candidate_nine, request_nine, facts_nine_count))
                                proof_nine = {'focus_id': focus_nine, 'kind': 'REVIEWED_SCOPE_CORRECTION',
                                    'candidate_sha256': hashed(candidate_nine), 'source_fact_check': gate(candidate_nine, request_nine, facts_nine_count),
                                    'active_directory': correction_prefix[len('prototype-pipeline/'):] + '/attempt-000001',
                                    'mapper_invocation': document(dir_nine / 'mapper.json')['invocation'],
                                    'retained_mapper_directory': 'epochs/epoch-000005/' + focus_nine,
                                    'reviewer_invocation': document(correction_dir / 'reviewer.json')['invocation'],
                                    'review_request_sha256': hashed(corrected_task), 'review_sha256': hashed(corrected_review),
                                    'review_receipt_sha256': hashed(checked), 'technical_evidence_sha256': hashed(screen_evidence),
                                    'review_correction_sha256': hashed(child)}
                                completed_requests = [req for req, _ in requests] + [request_nine]
                                completed_candidates = [*candidates_four, candidate_nine]
                                completed_proofs = [*proofs_eight, proof_nine]
                                cursor_later = cursor + len(owned_nine)

                                def ordinary_request(req, owned):
                                    refs = {obj['id'] for obj in owned}
                                    entries = [entry for entry in packet['sources'] if refs <= {obj['id'] for obj in entry['facts']['objects']}]
                                    need(len(entries) == 1); facts = entries[0]['facts']
                                    units = [unit for obj in owned for unit in facts['code_units'] if unit['owner_id'] == obj['id']]
                                    associated = refs | {unit['id'] for unit in units}
                                    links = [row for row in facts['links'] if row['source_id'] in associated]
                                    findings = [row for row in facts['findings'] if not row['object_ids'] or associated.intersection(row['object_ids'])]
                                    contexts = set()
                                    def ancestors(ref):
                                        seen = set()
                                        while ref is not None:
                                            need(ref in all_objects and ref not in seen); seen.add(ref); contexts.add(ref)
                                            ref = all_objects[ref]['parent_id']
                                    for obj in owned: ancestors(obj['parent_id'])
                                    for link in links:
                                        if link['status'] == 'resolved': ancestors(link['target_id'])
                                    for finding in findings:
                                        for ref in finding['object_ids']: ancestors(ref)
                                    supplied = {row['code_unit_id']: row for row in req['chunks']}
                                    need(len(supplied) == len(req['chunks'])); selected_chunks = []
                                    for unit in units:
                                        chunk = chunk_units[unit['id']]
                                        if chunk['id'] in selected['approved_chunk_hashes']:
                                            body = supplied[unit['id']]['text']
                                            need(type(body) is str and len(body.encode()) == unit['bytes']
                                                 and hashlib.sha256(body.encode()).hexdigest() == unit['sha256'])
                                            selected_chunks.append({**chunk, 'text': body})
                                    result = {'schema_version': 1, 'scope': 'fox-forms-focus-request-v1',
                                        'source_binding': selected['source_binding'],
                                        'focus_id': 'focus-' + hashed([selected['source_binding'], [obj['id'] for obj in owned]])[:24],
                                        'source_index': source_index, 'owned_objects': owned,
                                        'context_objects': [all_objects[ref] for ref in sorted(contexts - refs, key=object_order.__getitem__)],
                                        'code_units': units, 'links': links, 'dependencies': [row for row in facts['dependencies'] if row['source_id'] in associated],
                                        'findings': findings, 'chunks': selected_chunks,
                                        'unselected_code_unit_ids': [unit['id'] for unit in units if chunk_units[unit['id']]['id'] not in selected['approved_chunk_hashes']],
                                        'safety': requests[0][0]['safety']}
                                    result['focus_binding'] = hashed(result)
                                    same(req, result); need(len(canonical(req)) <= 500000)

                                def compact_context(audit):
                                    tables = {key: {} for key in ('sources', 'mappings', 'screens', 'owner_bindings')}
                                    def put(table, key, value):
                                        if key in tables[table]: same(tables[table][key], value)
                                        else: tables[table][key] = value
                                        return key
                                    def triple(source, mapping, binding):
                                        need(source['id'] == mapping['source_object_id'])
                                        return {'source_ref': put('sources', source['id'], source),
                                            'mapping_ref': put('mappings', source['id'], mapping),
                                            'owner_ref': put('owner_bindings', binding['focus_id'], binding)}
                                    header = json.loads(canonical({key: value for key, value in audit.items() if key != 'owned_rows'}))
                                    header['prefix_check']['reference_bindings'] = {key: put('owner_bindings', value['focus_id'], value)
                                        for key, value in header['prefix_check']['reference_bindings'].items()}
                                    rows = []
                                    for row in audit['owned_rows']:
                                        screen = row['screen_context']
                                        value = {'focus_id': row['focus_id'], **triple(row['source'], row['mapping'], row['owner_binding']),
                                            'ancestors': [triple(a['source'], a['mapping'], a['owner_binding']) for a in row['ancestors']],
                                            'screen_context': None, 'unit_coverage': row['unit_coverage']}
                                        if screen is not None:
                                            value['screen_context'] = {**triple(screen['source_block'], screen['owner_mapping'], screen['owner_binding']),
                                                'screen_ref': put('screens', screen['declaration']['id'], screen['declaration']),
                                                'borrowed_from_prior_focus': screen['borrowed_from_prior_focus']}
                                        rows.append(value)
                                    return {'schema_version': 1, 'scope': 'fox-compact-design-review-context-v1',
                                        'header': header, 'tables': tables, 'owned_rows': rows}

                                for position in range(9, 14):
                                    rest = ordered[cursor_later:]; need(rest)
                                    group = (rest[0]['block_id'], rest[0]['module_id']); owned_later = []
                                    for obj in rest:
                                        if (obj['block_id'], obj['module_id']) != group or len(owned_later) == 32: break
                                        owned_later.append(obj)
                                    fid = 'focus-' + hashed([selected['source_binding'], [obj['id'] for obj in owned_later]])[:24]
                                    directory = sixth_root / fid
                                    need(directory.is_dir()); protected(directory); epoch_directories.add(sixth_prefix + '/' + fid)
                                    req = document(directory / 'mapper-request.json', 500000)
                                    ordinary_request(req, owned_later); cursor_later += len(owned_later)
                                    raw, mapper_room = role_output(directory, 'mapper', req)
                                    need(mapper_room not in used_rooms); used_rooms.add(mapper_room)
                                    owned_ids = {obj['id'] for obj in owned_later}
                                    # This fixed terminal has no further alias/context
                                    # repair: the checked screen projection is NO_CHANGE.
                                    shape(raw, req, owned_ids)
                                    candidate = document(directory / 'projection-candidate.json')
                                    same(candidate, raw); same(document(directory / 'screen-input-candidate.json'), raw)
                                    summary_prior, _ = context_data(completed_proofs, context_requests=completed_requests,
                                        candidates=completed_candidates, all_reviewed=True)
                                    refs_prior = {key: {field: value for field, value in ref.items() if field != 'kind'}
                                        for key, ref in summary_prior['reference_bindings'].items()}
                                    summary, rows = context_data(completed_proofs, context_requests=[*completed_requests, req],
                                        candidates=[*completed_candidates, candidate], current_request=req, current_candidate=candidate)
                                    audit = {'schema_version': 1, 'scope': 'fox-design-review-context-v1', 'focus_id': fid,
                                        'source_binding': selected['source_binding'], 'target_profile_sha256': selected['target_profile_sha256'],
                                        'focus_request_sha256': hashed(req), 'candidate_sha256': hashed(candidate),
                                        'prefix_check': summary, 'owned_rows': rows, 'review_required': True, **context_false}
                                    same(document(directory / 'full-audit-context.json'), audit)
                                    screen = {'schema_version': 1, 'scope': 'fox-context-screen-projection-v1',
                                        'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
                                        'focus_id': fid, 'focus_request_sha256': hashed(req), 'target_profile_sha256': selected['target_profile_sha256'],
                                        'raw_candidate_sha256': hashed(raw), 'candidate_sha256': hashed(candidate), 'status': 'NO_CHANGE',
                                        'removed_screens': [], 'prior_prefix_sha256': hashed(completed_candidates),
                                        'prior_references_sha256': hashed(refs_prior), 'prior_prefix_check_sha256': hashed(summary_prior),
                                        'derived_review_context_sha256': hashed(audit), 'only_screen_declarations_changed': True,
                                        'raw_model_output': False, 'independent_review_required': True, 'semantic_equivalence_asserted': False,
                                        'caller_must_reconstruct_prior_reviewed_views': True, 'caller_must_preserve_originals': True,
                                        'ai_approval_granted': False, **context_false}
                                    same(document(directory / 'screen-projection-receipt.json'), screen)
                                    evidence = {'schema_version': 1, 'scope': 'fox-focus-context-screen-normalization-v1',
                                        'base_technical_evidence': None, 'context_screen_projection': screen, 'raw_mapper_candidate_sha256': hashed(raw)}
                                    same(document(directory / 'projection-receipt.json'), evidence)
                                    task = {'schema_version': 1, 'scope': 'fox-partition-review-task-v1', 'request': req,
                                        'candidate': candidate, 'candidate_sha256': hashed(candidate),
                                        'target_profile_sha256': selected['target_profile_sha256'], 'design_context_sha256': hashed(audit),
                                        'design_context': compact_context(audit), 'task_guidance': guidance,
                                        'independent_semantic_review_required': True, 'historical_allegations': None, **context_false,
                                        'review_context': {'schema_version': 1, 'scope': 'fox-focus-extended-review-v1',
                                            'operation': 'projection_review', 'raw_candidate': raw, 'raw_candidate_sha256': hashed(raw),
                                            'evidence': evidence, 'trusted_requirements': {
                                                'source_fact_values_and_every_ref_must_match_exact_whitelist': True,
                                                'old_ai_approval_is_not_source_validation': True,
                                                'review_every_required_clause_body_conditions_effects_and_action_refs': True,
                                                'generic_or_relabelled_unsupported_facts_must_be_changes_required': True,
                                                'external_semantics_must_remain_uncertain': True,
                                                'compare_both_rationales_no_semantic_equivalence_from_machine_match': True,
                                                'never_repair_candidate_or_accept_business_behavior': True}}}
                                    task['ownership_ledger'] = ledger(req, task['design_context'])
                                    task['task_guidance'] += (' The explicit ownership_ledger distinguishes owned objects from context-only '
                                        'objects and inherited screens. Only owned IDs (or null for a global finding) may be used in '
                                        'findings. Context grants no ownership. Reject genuine semantic defects; do not force approval.')
                                    task['task_binding'] = hashed(task)
                                    need(len(json.dumps(task, ensure_ascii=False, allow_nan=False).encode()) <= 650000)
                                    same(document(directory / 'reviewer-request.json'), task)
                                    output, reviewer_room = role_output(directory, 'reviewer', task)
                                    need(reviewer_room not in used_rooms); used_rooms.add(reviewer_room)
                                    verdict = 'APPROVED' if position < 13 else 'CHANGES_REQUIRED'
                                    need(set(output) == {'source_binding', 'focus_binding', 'candidate_sha256', 'verdict', 'findings'}
                                         and output['source_binding'] == selected['source_binding'] and output['focus_binding'] == req['focus_binding']
                                         and output['candidate_sha256'] == hashed(candidate) and output['verdict'] == verdict
                                         and type(output['findings']) is list and len(output['findings']) <= 250
                                         and bool(output['findings']) == (verdict == 'CHANGES_REQUIRED'))
                                    for finding in output['findings']:
                                        need(type(finding) is dict and set(finding) == {'source_object_id', 'code', 'detail'}
                                             and (finding['source_object_id'] is None or finding['source_object_id'] in owned_ids))
                                        identifier(finding['code']); text(finding['detail'])
                                    checked = review_receipt(candidate, req, verdict)
                                    same(document(directory / 'review-receipt.json'), checked)
                                    count = sum(claim['status'] == 'source_fact' for claim in candidate['blueprint']['claims'])
                                    source_gate = gate(candidate, req, count)
                                    same(document(sixth_root / 'source-facts' / (fid + '.json')), source_gate)
                                    completed_requests.append(req); completed_candidates.append(candidate)
                                    completed_proofs.append({'focus_id': fid, 'candidate_sha256': hashed(candidate),
                                        'source_fact_check': source_gate, 'review_request_sha256': hashed(task),
                                        'review_sha256': hashed(output), 'review_receipt_sha256': hashed(checked),
                                        'active_directory': 'epochs/epoch-000006/' + fid,
                                        'mapper_invocation': document(directory / 'mapper.json')['invocation'],
                                        'reviewer_invocation': document(directory / 'reviewer.json')['invocation'],
                                        'technical_evidence_sha256': hashed(evidence)})
                                need(len(completed_proofs) == 14 and len(completed_candidates) == 14)
                                archived_latest = False
                                physical_latest = document(job / 'prototype-result.json')
                                expected_latest = {**latest, 'mapping_epoch_sha256': hashed(sixth),
                                    'blocked_focus_id': completed_requests[-1]['focus_id']}
                                same(physical_latest, expected_latest)
                                final_history = 'prototype-results/' + hashed(physical_latest) + '.json'
                                same(document(job / final_history), physical_latest)
                                need(observed[final_history] == observed['prototype-result.json'])
                                same(document(job / 'prototype-result-publications/epoch-000006/publication.json'), {
                                    'schema_version': 1, 'scope': 'fox-prototype-epoch-result-publication-v1', 'job_id': run['id'],
                                    'project_id': run['project'], 'source_hash': run['source_hash'], 'source_binding': selected['source_binding'],
                                    'epoch_sha256': hashed(sixth), 'screen_projection_sha256': hashed(screen_receipt),
                                    'result_sha256': hashed(physical_latest), 'history_path': final_history, 'status': 'CHANGES_REQUIRED',
                                    'stage': 'reviewing', 'active_proofs_sha256': hashed(completed_proofs), 'stage_files': {}, 'previous_result': sixth_pin})
                                need(len(observed) == 251)
            allowed = set(observed) | {'prototype-pipeline', 'prototype-pipeline/sources'} | {
                'prototype-pipeline/' + directory.name for _, directory in requests} | epoch_directories
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


def terminal_prototype_clause_repair(database, db, run):
    """Read-only epoch-two deletion-only failure; no continuation authority."""
    return terminal_empty_prototype_mapping(database, db, run, clause_repair_failure=True)


def terminal_prototype_container_review(database, db, run):
    """Only epoch three's sealed projection rejection, never epoch-four authority."""
    return terminal_empty_prototype_mapping(database, db, run, container_review_failure=True)


def terminal_prototype_partition_review(database, db, run):
    """Only epoch four's sealed CHANGES_REQUIRED stop; no retry/adoption grant."""
    return terminal_empty_prototype_mapping(database, db, run, partition_review_failure=True)


def terminal_prototype_context_screen(database, db, run):
    """Only head five's complete mapper-nine duplicate stop, never a projection."""
    return terminal_empty_prototype_mapping(database, db, run, context_screen_failure=True)


def terminal_prototype_review_scope(database, db, run):
    """Only head six's sealed non-owned reviewer finding; no correction grant."""
    return terminal_empty_prototype_mapping(database, db, run, review_scope_failure=True)


def terminal_prototype_post_correction_review(database, db, run):
    """Sealed consumed correction plus14-section negative; no retry/approval grant."""
    return terminal_empty_prototype_mapping(database, db, run, post_correction_review_failure=True)


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
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_empty_prototype_mapping(self.database, db, dict(run), analysis_epoch_failure=True)):
            return {'blocks_admission': False, 'recovery_state': 'prototype_mapping_analysis_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_clause_repair(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_clause_repair_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_container_review(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_container_review_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_partition_review(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_partition_review_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_context_screen(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_context_screen_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_review_scope(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_review_scope_terminal', 'retry_eligible': False}
        if (run['state'] == 'ATTENTION' and run['artifact'] is None and legacy is None and closed is None and retry is None
                and terminal_prototype_post_correction_review(self.database, db, dict(run))):
            return {'blocks_admission': False, 'recovery_state': 'prototype_post_correction_review_terminal', 'retry_eligible': False}
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
