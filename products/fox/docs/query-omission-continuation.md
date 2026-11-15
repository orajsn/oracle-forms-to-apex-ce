# Continue a partial prototype with query omissions

This bounded route handles a saved initial mapping where the model asserted a
redacted block filter and ordering as proven facts. It does not apply to every
mapping failure and does not recover hidden business rules.

In the stopped run, choose **Check repair plan**. If eligible, FOX explains that
the original filter and sorting are **not implemented**. Review the source scope,
confirm processing permissions, and explicitly approve those omissions before
choosing **Continue with query omissions**.

FOX keeps the same run, original source and model response. Completed mapping
calls are not repeated. A fresh independent reviewer checks the derived partial
design; the untouched remaining sections then continue. Normal SQLcl validation,
non-overwriting import, runtime checks and export gates still apply.

Ask the application owner for a non-sensitive specification of the filter,
runtime-global initialization and expected ordering before implementing that
behavior. Do not restore masked values during a demo or assume the generated
prototype is business-equivalent.

The route refuses changed sources, targets or checkpoints; prior review attempts;
out-of-order or unknown operations; missing consent; and already-started target
work at initial admission. Refreshing is not a retry. If a submitted request has
an unknown outcome, check the existing run and ask the operator to reconcile it.

Other projects' stopped prototypes do not automatically force a restart or
cleanup. For this exact continuation, FOX checks their existing converter state
read-only and rechecks retained evidence before queueing. Unknown or active work
still blocks. Those projects receive no retry permission and remain unchanged.

Generated output, technical verification and human business acceptance remain
separate. Local authored-provider tests and read-only real-candidate derivation
do not establish a successful live review, Oracle import or exact-package reimport.
