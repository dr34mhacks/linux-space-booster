# Linux Space Booster — Development Roadmap

## Purpose

This roadmap turns Linux Space Booster from a large, Debian-focused cleanup
script into a safe, modular disk-maintenance tool. The priority is trust:
analyse first, preview exact changes, clean only with clear consent, and report
what the filesystem actually recovered.

## Guiding rules

- Do not delete user data, configuration, evidence, or an active system file.
- Route every destructive action through one central safety layer.
- Prefer a tool's supported cleanup command over manually deleting its files.
- Keep potentially destructive categories opt-in; they never belong in the
  default safe cleanup.
- Support dry runs, actionable errors, logs, and stable exit codes for every
  non-interactive command.
- Do not claim support or safety guarantees until they are tested.

## Phase 1 — Safety and CLI foundation

**Goal:** Make the current script predictable, reviewable, and safe before
adding more cleanup targets.

### Work items

1. Separate argument parsing from execution.
   - Parse all flags first, validate combinations, then run preflight and the
     chosen operation.
   - Retain the existing commands (`--quick`, `--advanced`, `--user-only`,
     `--dry-run`, `--force`, and `--help`) while documenting any changed
     behaviour.
   - Establish the new command model: `--analyze`, `--clean`, `--profile`,
     `--category`, `--json`, `--version`, and `--help`.
2. Define a single privilege policy.
   - Root-only system cleanup runs as root and must not call `sudo` internally.
   - User-only and analysis commands work without root where possible.
   - Return a distinct insufficient-privileges exit code when required.
3. Create the deletion/safety API.
   - Add helpers such as `safe_remove_file`, `safe_remove_dir_contents`, and
     `safe_find_delete`.
   - Validate canonical paths, reject protected locations, prevent empty or
     glob-expanded targets, preserve parent directories, and log every action.
   - Replace direct `rm`, destructive `find`, and unsafe wildcard operations.
   - Ensure directory cleanup includes hidden entries without deleting the
     directory itself.
4. Standardise module behaviour.
   - Each module must discover candidates, estimate reclaimable space, preview,
     execute through the safety API, and report success/failure consistently.
   - Record per-module estimates separately from filesystem-level recovery.
5. Improve reports and exit handling.
   - Measure free space before and after on the affected filesystem using
     `df`; present that as actual recovered space.
   - Use exit codes: `0` success, `1` general error, `2` invalid arguments,
     `3` insufficient privileges, `4` unsupported system, `5` partial failure,
     `6` cleanup failure.
6. Establish test and shell-quality checks.
   - Add ShellCheck and `bash -n` checks.
   - Add tests for argument parsing and safety helpers, including empty paths,
     hidden files, protected paths, dry-run, and paths containing spaces.

### Completion criteria

- No cleanup module invokes `sudo`, `rm`, or destructive `find` directly.
- `--dry-run` changes no files and displays the intended actions.
- Options work reliably in any order when their combination is valid.
- Actual recovered space is shown from filesystem free-space measurements.
- The test suite and static shell checks pass.

## Phase 2 — Platform detection and package-manager abstraction

**Goal:** Make the Linux claim accurate rather than Debian-only.

### Work items

1. Detect OS, init system, available tools, and package manager without
   assuming they are installed.
2. Introduce package-manager adapters for APT, DNF, Pacman, and APK.
3. Move Debian-specific features (DPKG, APT cache, and kernel handling) behind
   explicit capability checks.
4. Define a clear unsupported/degraded-mode message when no adapter exists.
5. Test each adapter in a container or VM fixture where practical.

### Completion criteria

- Unsupported commands are skipped with a reason, never executed blindly.
- APT remains fully functional; other supported adapters expose only verified
  safe operations.
- README support claims match the tested platforms.

## Phase 3 — Modular cleanup engine

**Goal:** Replace the monolithic script structure with small, auditable units.

### Work items

1. Split core functionality into `lib/` (CLI, logging, safety, detection,
   reporting) and cleanup modules into `modules/`.
2. Give each module metadata: name, category, required privilege, risk level,
   availability check, estimate function, and execute function.
3. Migrate existing APT, logs/journal, temporary files, browser caches,
   thumbnails, Snap, PostgreSQL, Metasploit, Wireshark, and user caches one at
   a time without changing their intended scope.
4. Introduce a module registry so the CLI and interactive UI list the same
   capabilities.

### Completion criteria

- The entry script orchestrates rather than contains cleanup implementation.
- Every module can be analysed, dry-run, and run independently.
- Migrated module behaviour is covered by tests or documented manual checks.

## Phase 4 — Analyze-first experience

**Goal:** Help users understand their disk usage before asking them to delete
anything.

### Work items

1. Add `--analyze` as a non-destructive command.
2. Report filesystem capacity/free space, largest top-level directories, and
   available cleanup opportunities with estimates.
3. Add an exact-action `--dry-run` report grouped by module.
4. Add `--json` for analysis and cleanup summaries with byte values and module
   statuses suitable for automation.
5. Ensure analysis handles permission-denied paths gracefully.

### Completion criteria

- `--analyze` never modifies the system.
- Human and JSON reports agree on totals and statuses.
- Users can identify what will be cleaned before they choose `--clean`.

## Phase 5 — Profiles and targeted categories

**Goal:** Offer useful defaults without hiding risk.

### Profiles

| Profile | Scope |
| --- | --- |
| `safe` | Package caches, old logs, thumbnails, age-qualified temporary files, and verified safe application caches. |
| `desktop` | Safe profile plus browser caches, desktop application caches, unused Flatpak runtimes, and eligible Snap revisions. |
| `developer` | Safe profile plus supported development-tool caches and explicitly selected Docker build-cache cleanup. |
| `aggressive` | Opt-in categories with a separate confirmation for each category. |

### Work items

1. Add `--profile NAME` and `--category NAME`; validate their combinations.
2. Add Flatpak unused-runtime cleanup using `flatpak uninstall --unused` as a
   clearly labelled operation.
3. Add developer-cache modules using official cache-cleaning commands where
   possible (npm, pnpm, Yarn, pip, uv, Poetry, Cargo, Go, Composer, Maven,
   Gradle, NuGet, Flutter, and Dart).
4. Add Docker inspection first; make cleanup choices granular: build cache,
   stopped containers, dangling images, unused networks, and unused volumes.
5. Keep Docker, volumes, package autoremove, kernels, and aggressive profiles
   out of default quick/safe cleanup.

### Completion criteria

- Every profile expands to a visible, documented module list.
- High-impact categories require explicit opt-in and confirmation unless an
  intentional non-interactive override is supplied.
- A missing optional tool produces a skip, not an error.

## Phase 6 — Kernel and system-journal controls

**Goal:** Make sensitive system maintenance transparent and conservative.

### Work items

1. Add configurable journal retention options such as `--journal-days` and
   `--journal-size`, with safe defaults and a preview of the current size.
2. Replace kernel cleanup based only on `apt autoremove` with an explicit
   inventory: current kernel, retained fallback kernels, and proposed removals.
3. Require an explicit confirmation for kernel removal; never remove the
   running kernel.
4. Clearly distinguish cache cleanup from package or runtime removal.

### Completion criteria

- Kernel removal output states exactly what is kept and why.
- Journal actions honour supplied retention limits.
- No sensitive operation is silently included in the safe profile.

## Phase 7 — Interactive UI, documentation, and release readiness

**Goal:** Make the tool easy to use, honest in its documentation, and ready
for contributors.

### Work items

1. Rebuild the interactive menu on top of the same CLI/module engine.
2. Add an accessible non-colour output mode and retain usable output on a dumb
   terminal.
3. Update README usage, platform support, safety boundaries, profiles, exit
   codes, examples, and recovery expectations.
4. Add contributor guidance, a changelog, release/version process, and a test
   matrix.
5. Add CI for shell syntax, ShellCheck, and tests.
6. Review all safety claims against the final implementation; remove claims
   that cannot be guaranteed.

### Completion criteria

- Interactive and CLI paths produce equivalent results.
- Documentation is accurate for the released version.
- CI is green and a clean install/use smoke test succeeds.

## Suggested delivery order

1. Complete Phase 1 before introducing new cleanup targets.
2. Complete Phase 2 and Phase 3 before presenting broad cross-distribution
   support.
3. Deliver Phase 4 before adding aggressive profiles or Docker cleanup.
4. Deliver Phases 5 and 6 as opt-in features with focused tests.
5. Finish Phase 7 before a public release or major version bump.

## Non-goals for the first refactor

- A GUI frontend; JSON output provides a stable foundation for one later.
- Automatically deleting personal files, downloads, media, or project data.
- Default Docker-volume removal, kernel removal, or aggressive package removal.
- Claiming every Linux distribution is supported without verified adapters.
