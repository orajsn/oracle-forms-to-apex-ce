#!/usr/bin/env python3
"""Observe fresh runtime requests; claimed/uncertain work is never replayed."""
import json
import time
from qa.operator.direct_preview_runtime import configure
from qa.operator.prototype_runtime_worker import run_once
from forms2apex.prototype_runtime_bridge import REQUEST, MAX_JSON, object_bytes, remaining_seconds


def poll_once(config):
    observations=[]
    for job in config.io.pending(limit=100):
        try:
            remaining_seconds(object_bytes(config.io.read(job,REQUEST,MAX_JSON)))
        except RuntimeError:
            # Expired or malformed retained packets cannot be executed, claimed,
            # rewritten or allowed to prevent the user opening the FOX UI.
            observations.append({'job_id':job,'state':'RETAINED_REQUEST_NEEDS_RECONCILIATION'})
            continue
        try:
            result=run_once(config,job)
            observations.append({'job_id':job,'state':result['state']})
        except Exception:
            # run_once durably claims before effects. Never replay its claim or
            # expose browser/credential diagnostics in the supervisor log.
            observations.append({'job_id':job,'state':'RUNTIME_OUTCOME_UNCONFIRMED_NO_REPLAY'})
        break
    return observations


def main():
    previous=None
    while True:
        observations=poll_once(configure())
        if observations and observations!=previous:
            print(json.dumps({'runtime':observations}),flush=True)
        previous=observations
        time.sleep(2)


if __name__=='__main__':
    main()
