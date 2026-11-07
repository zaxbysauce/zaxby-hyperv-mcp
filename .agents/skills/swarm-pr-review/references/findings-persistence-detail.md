# Review Finding Persistence enforced order and error reporting


**Enforced order, dispositions, and error reporting (Profile A).** The
trigger evaluation must complete before every findings boundary EXCEPT the
base-only `post_explorer` write above, which is admissible right after base
settlement (issue #2280); beyond that exception checkpoints run strictly
`post_explorer` → `post_reviewer` → `post_critic`, each requiring the prior
checkpoint persisted, and `post_reviewer`/`post_critic` must exactly cover
the FULL (base+micro) candidate inventory against the persisted trigger-eval
artifact; records must match the authoritative reviewer/critic
verdict rows, and an invalid payload is rejected in ONE call listing every
violation as `finding_id: field expected <value>, got <value>`. Full contract
(write order, dispositions, severity authority table, handoff schema):
references/findings-persistence-contract.md.
