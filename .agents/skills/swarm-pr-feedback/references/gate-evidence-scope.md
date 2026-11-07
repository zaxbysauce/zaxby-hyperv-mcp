# Why gate evidence is not item-scoped

Stage A, Stage B, and closeout evidence invalidate as whole gate batches, not
per feedback item, and that is a deliberate design decision, not unfinished
work:

- **No trustworthy item-to-file mapping exists to key invalidation on.** The
  file scope a caller declares for a feedback item is caller-asserted and
  only path-sanitized — it is never intersected with the actual changed-file
  set, and it carries no persisted binding back to feedback item IDs. Keying
  invalidation on that declaration would let a controller dodge
  re-verification by under-declaring scope, turning a fail-closed guarantee
  into a fail-open one (AGENTS.md invariant 9) — the same failure class that
  already ruled out keying digest invalidation on `git diff --raw` blob OIDs.
- **The four gate phases are holistic by contract.** Each recorded batch must
  own every inventory item exactly once and in declared order. Retaining
  evidence for a subset of items per gate would re-partition that
  independent-review contract itself, and would need its own
  collusion/independence analysis before it could be trusted — it is not a
  drop-in extension of the revision-level retention above.
