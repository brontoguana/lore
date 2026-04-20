# Document CLI Ergonomics Changes

Temporary implementation note for the Lore document/block CLI changes agreed on April 20, 2026.

## Goals

- Replace the current document marker format with a terminal-friendly `@@block` / `@@end` format.
- Make block creation default to append instead of start-of-document insertion.
- Expose explicit insertion modes so callers can choose `start`, `append`, or `after <block-id>`.
- Add safer stdin/file handling so `docs write` cannot accidentally wipe a document because input was empty or missing.
- Reduce shell quoting pain by letting block content come from `--file` or `--stdin`.
- Update help text and tests so the new behavior is discoverable and verified.

## Implemented Shape

1. Document text now renders as:

   ```text
   @@block id=<id> type=<type>
   ...content...
   @@end
   ```

2. The parser accepts the new `@@block` format and still accepts the legacy `<<<< block:... >>>>` format during rollout.
3. `blocks create` now defaults to append.
4. `blocks create` now exposes explicit placement through `--position start|append|after`, with `--after <block-id>` used for the `after` case.
5. `blocks create` accepts content from positional text, `--file`, or `--stdin`.
6. `blocks update` accepts content from positional text, `--file`, or `--stdin`.
7. `docs write` now supports `--file` and `--stdin`, rejects empty input by default, and fails clearly on interactive TTY stdin.
8. CLI help text and tests were updated to reflect the new marker format and input/placement behavior.

## Follow-up

1. Update any remaining docs, prompts, or API schemas that still describe the old marker shape or old placement semantics.
2. Decide whether to keep accepting the legacy marker format indefinitely or remove it after downstream callers are updated.
