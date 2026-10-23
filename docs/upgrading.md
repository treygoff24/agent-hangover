# Upgrading an existing campaign

Version 0.1.1 uses `hang-` card IDs instead of `dslp-`. The hash after the
prefix stays the same. Existing 0.1.0 campaigns need migration before you
run campaign commands with 0.1.1; otherwise commands such as `fix` and
`packet` refuse the old IDs.

For a new campaign, install normally. For an existing campaign, keep its
backlog and decisions with the migration utility below. It ships in both the npm install and the source checkout. It needs Python
3.11+, Git 2.42+ and a regular clone. Linked worktrees and submodules are
refused, as in static mode. If your campaign is in one, keep it in place and
plan a separate move to a regular clone; copying state alone does not update
its repository path or owner binding.

## Migrate once per repository

1. Stop any hangover command or agent working on the campaign. Install the
   new version, but leave campaign commands stopped until migration is done.
2. If the state folder still has the pre-release name `.deslop`, inspect it
   and rename it to `.hangover` only when no `.hangover` entry exists. If both
   exist, stop and decide which campaign to preserve; never merge them by
   copying one over the other.
3. Preview the migration. Replace `/path/to/repository` with the repository
   whose campaign you want to keep:

   ```bash
   python3 "$(npm root -g)/agent-hangover/scripts/migrate-state.py" /path/to/repository
   ```

   From a source checkout, use `python3 scripts/migrate-state.py
   /path/to/repository` instead. Run the utility from the trusted hangover
   installation, never a copy supplied by the repository being inspected.
   Read the planned file changes and any warnings. A dry run writes nothing.
4. Apply the same plan:

   ```bash
   python3 "$(npm root -g)/agent-hangover/scripts/migrate-state.py" /path/to/repository --apply
   ```

   The utility first copies the campaign records it can migrate to a sibling
   backup named
   `.hangover.pre-migrate-<timestamp>`, then changes the files in place. It
   preserves the state directory itself because its owner marker is bound
   to that directory. Keep the printed backup path; it contains private
   campaign material and must not be committed. Add that exact directory
   name to the repository's local `.git/info/exclude` if needed.
5. From the migrated repository, run `hangover status` and `hangover next`.
   Check that the backlog and current batch are present and IDs start with
   `hang-`. Run the utility again without `--apply`; it should report
   `nothing to migrate`. Keep the backup until you have checked the result.

The backup covers `config.json`, `state.json`, its lock, the owner marker,
`gate-proofs.json`, and the `runs/` and `fixes/` trees when present. Other
scratch and cache directories are left alone and are not backed up. Raw
logs and captures are retained without reading or rewriting their contents.

The utility changes card references in state, snapshots and fix packets,
renames fix directories, and updates a recognized old owner marker. It does
not invent an owner marker or change product code. It refuses tracked
state, links, special files, malformed state, conflicting names and a held
campaign lock. A refusal is a reason to stop and inspect the stated problem.
Files read for migration are limited to 64 MiB each by default. For a known
large history, add `--max-file-mib 256` to both the preview and `--apply`
commands. The option accepts integers from 1 to 1024. This is a per-file
input limit, not a RAM limit: parsing and retained rewrites can use several
times the input size, and memory grows with the number of planned rewrites.

If an apply fails after printing a backup, keep both directories and stop
campaign work. Recovery must preserve the original `.hangover` directory
and its owner binding; do not replace it with the backup directory blindly.

## After migration

Saved verification and review proofs refer to the old tool and files.
Re-run `hangover verify` for an active batch, or the relevant audit, before
closing work. Migration preserves decisions; it does not certify old proofs
under the new version.

If the utility reports `.deslop-rust.json`, review that repository policy
file. Hangover reads `.hangover-rust.json`; rename the old file only after
confirming there is no existing policy to overwrite. Commit that rename as
a normal repository change. The state utility leaves policy files alone.

To start fresh instead of migrating, first preserve the old campaign in a
private backup outside the checkout and confirm that losing its active
backlog is intended. Then create a new campaign. Keep the old state until
you have verified the replacement; a fresh campaign does not carry prior
fixes, deferrals or review history forward.
