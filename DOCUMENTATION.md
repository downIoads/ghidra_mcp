# GhidraMCP Completed Work

This document records implemented GhidraMCP capabilities.

## Current Tool Surface

Read and navigation tools currently exposed:

- `program_info`
- `list_methods`
- `list_functions`
- `list_classes`
- `list_namespaces`
- `list_segments`
- `list_imports`
- `list_exports`
- `list_data_items`
- `list_strings`
- `search_functions_by_name`
- `get_current_address`
- `get_current_function`
- `get_function_by_address`
- `get_address_info`
- `get_instruction_at`
- `get_instructions`
- `get_data_at`
- `get_function_details`
- `list_function_variables`
- `decompile_function`
- `decompile_function_by_address`
- `disassemble_function`
- `get_xrefs_to`
- `get_xrefs_from`
- `get_function_xrefs`
- `list_symbols`
- `search_symbols`
- `get_symbol`
- `list_comments`
- `list_bookmarks`
- `get_references`
- `list_data_types`
- `search_data_types`
- `get_data_type`
- `get_struct_layout`
- `get_enum_values`
- `get_typedef_target`
- `read_bytes`
- `find_bytes`

Write and analysis tools currently exposed:

- `rename_function`
- `rename_function_by_address`
- `rename_data`
- `rename_variable`
- `set_function_prototype`
- `set_local_variable_type`
- `set_decompiler_comment`
- `set_disassembly_comment`
- `set_comment`
- `set_label`
- `delete_label`
- `set_primary_symbol`
- `create_namespace`
- `rename_namespace`
- `create_reference`
- `delete_reference`
- `set_reference_primary`
- `create_memory_reference`
- `create_stack_reference`
- `create_external_reference`
- `set_function_name`
- `set_function_return_type`
- `set_function_calling_convention`
- `set_function_no_return`
- `set_function_inline`
- `set_function_varargs`
- `set_function_thunk`
- `set_function_comment`
- `list_parameters`
- `rename_parameter`
- `set_parameter_type`
- `set_parameter_storage`
- `add_parameter`
- `remove_parameter`
- `reorder_parameters`
- `rename_local_variable_by_storage`
- `set_local_variable_type_by_storage`
- `create_stack_variable`
- `delete_stack_variable`
- `set_stack_variable_type`
- `apply_data_type`
- `create_struct`
- `delete_struct`
- `rename_data_type`
- `add_struct_field`
- `rename_struct_field`
- `set_struct_field_type`
- `delete_struct_field`
- `create_enum`
- `set_enum_value`
- `create_typedef`
- `create_pointer_type`
- `create_array_type`
- `create_function_definition_type`
- `write_bytes`
- `clear_listing`
- `disassemble`
- `set_tmode`
- `set_tmode_range`
- `create_function`
- `delete_function`
- `create_label`
- `create_data`
- `analyze`
- `set_image_base`
- `create_initialized_block`
- `create_uninitialized_block`
- `remove_memory_block`
- `set_block_permissions`
- `create_function_range`
- `set_function_body`
- `add_function_body_range`
- `remove_function_body_range`
- `repair_function_body`
- `create_union`
- `delete_union`
- `add_union_field`
- `rename_union_field`
- `set_union_field_type`
- `delete_union_field`
- `clear_data`
- `create_string`
- `create_array`
- `list_analyzers`
- `get_analyzer_options`
- `set_analyzer_option`
- `enable_analyzer`
- `disable_analyzer`
- `run_analyzer`
- `analyze_range`
- `analyze_function`
- `get_analysis_status`
- `get_analysis_log`
- `list_undefined_ranges`
- `list_executable_undefined_ranges`
- `find_possible_functions`
- `find_pointer_tables`
- `find_jump_tables`
- `find_ascii_strings`
- `find_utf16_strings`
- `string_table_at`
- `list_open_programs`
- `select_program`
- `save_program`
- `close_program`
- `import_file`
- `open_program`
- `export_bytes`
- `export_patched_binary`
- `export_symbols`
- `export_function_map`
- `export_c_header`
- `export_analysis_report`
- `assemble_instruction`
- `patch_instruction`
- `nop_range`
- `patch_call_target`
- `patch_branch_target`
- `create_patch_record`
- `list_patches`
- `revert_patch`
- `project_info`
- `open_project`
- `close_project`
- `create_project`
- `save_project`
- `list_project_files`
- `project_file_exists`
- `delete_project_file`
- `list_loaders`
- `list_languages`
- `list_compiler_specs`
- `start_analysis`
- `analysis_progress`
- `cancel_analysis`
- `ready`
- `goto`
- `select_range`
- `ensure_gba_memory_map`
- `bring_up`
- `propagate_ldr_pc_refs`
- `create_thumb_function_from_pointer`
- `scan_thumb_pointer_table`
- `agent_hints`

## Implemented Phase 1: High-Value Read Primitives

### `get_address_info`

Given an address, returns a structured summary:

- Address, memory block, permissions, initialized/uninitialized status.
- Containing function, symbol, primary label, namespace, and source type.
- Code unit kind: instruction, defined data, undefined data, external, or invalid.
- Bytes at the address.
- Existing comments at all comment slots.
- Xrefs to and from the address.

### `get_instruction_at`

Given an address, returns:

- Address, mnemonic, operand strings, length, bytes.
- Fallthrough address.
- Flow type and destination addresses.
- Pcode operations if available.
- Containing function and current comments.

### `get_instructions`

Given `start`, optional `end`, and optional `limit`, returns a structured instruction listing.

### `get_data_at`

Given an address, returns:

- Data type path, length, value representation, raw bytes.
- Label/path name, parent structure info if applicable.
- Component fields if the address is inside a struct or array.

### `get_function_details`

Given a function address or name, returns:

- Name, entry, body ranges, signature, return type, calling convention.
- Parameters, locals, stack variables, storage, source type.
- Function flags: thunk, external, no-return, inline, varargs.
- Callers, callees, referenced strings, referenced data, and outbound references.
- Current comments and plate comment.

### `list_function_variables`

Exposes decompiler parameters and locals with:

- Name, data type, storage, size, source type.
- Whether the symbol is a parameter, local, global, or temporary.
- Representative varnodes if available.

## Implemented Phase 2: Symbol, Comment, Bookmark, and Reference Reads

### `list_symbols` and `search_symbols`

Support filtering by:

- Name substring.
- Symbol type: function, label, data, namespace, class, external, parameter, local.
- Address range or memory block.
- Source type: default, analysis, imported, user-defined.

Return address, name, namespace, symbol type, source type, primary flag, and containing function.

### `get_symbol`

Returns complete symbol details by name or address, including all symbols at an address and which one is primary.

### `list_comments`

Returns comments across the program or within a range/function:

- Plate, pre, post, EOL, and repeatable comments.
- Address, containing function, and comment text.

### `list_bookmarks`

Returns Ghidra bookmarks by category/type, address, text, and containing function.

### `get_references`

Unifies `get_xrefs_to`, `get_xrefs_from`, and function xrefs into one structured API with direction, reference type, operand index, source type, from/to symbols, and containing functions.

## Implemented Phase 3: Core Annotation Writes

### Comments

Added generalized `set_comment` endpoint:

- Address.
- Comment type: plate, pre, post, eol, repeatable.
- Text.
- Mode: replace, append, prepend, or clear.

The older comment endpoints remain as convenience wrappers.

### Labels and Symbols

Added:

- `set_label` with namespace, primary-symbol control, and source type.
- `delete_label`.
- `set_primary_symbol`.
- `create_namespace`.
- `rename_namespace`.

### References

Added:

- `create_reference`.
- `delete_reference`.
- `set_reference_primary`.
- `create_memory_reference`.
- `create_stack_reference`.
- `create_external_reference`.

Parameters include from address, to address, reference type, operand index, and source type where applicable.

## Implemented Phase 4: Function Editing Writes

### Function Metadata

Added:

- `set_function_name` by address with namespace support.
- `set_function_return_type`.
- `set_function_calling_convention`.
- `set_function_no_return`.
- `set_function_inline`.
- `set_function_varargs`.
- `set_function_thunk`.
- `set_function_comment`.

### Parameters

Added:

- `list_parameters`.
- `rename_parameter`.
- `set_parameter_type`.
- `set_parameter_storage`.
- `add_parameter`.
- `remove_parameter`.
- `reorder_parameters`.

### Locals and Stack Variables

Added:

- `rename_local_variable_by_storage`.
- `set_local_variable_type_by_storage`.
- `create_stack_variable`.
- `delete_stack_variable`.
- `set_stack_variable_type`.

## Implemented Phase 5: Data Type Reads and Writes

### Type Reads

Added:

- `list_data_types`.
- `search_data_types`.
- `get_data_type`.
- `get_struct_layout`.
- `get_enum_values`.
- `get_typedef_target`.

Return full category paths, sizes, descriptions, field offsets, field names, field types, packing, and source archives when available.

### Type Writes

Added:

- `create_struct`.
- `delete_struct`.
- `rename_data_type`.
- `add_struct_field`.
- `rename_struct_field`.
- `set_struct_field_type`.
- `delete_struct_field`.
- `create_enum`.
- `set_enum_value`.
- `create_typedef`.
- `create_pointer_type`.
- `create_array_type`.
- `create_function_definition_type`.

### Applying Data Types

Added:

- `apply_data_type(address, type_path, length?, clear_mode?)`.

## Implemented Phase 6: Function Body Repair

Tools for fixing function boundaries when auto-analysis got them wrong (common in
firmware, obfuscated binaries, hand-written assembly, and switch-heavy code).

- `create_function_range(entry, start|ranges, end?, name?, source?)` — create or
  update a function at `entry` with an explicit body range. Ranges can be a
  single `start`/`end` pair or comma-separated `start-end` pairs.
- `set_function_body(function_address|function_name, start|ranges, end?)` —
  replace a function body with the supplied range(s). Entry must remain inside.
- `add_function_body_range(function_address|function_name, ranges...)` — extend
  a function body with extra ranges.
- `remove_function_body_range(function_address|function_name, ranges...)` —
  subtract ranges from a function body. The entry point may not be removed.
- `repair_function_body(function_address|function_name)` — re-run
  `CreateFunctionCmd.fixupFunctionBody`, recomputing the body by following flow
  from the entry point.

All five return a structured summary with `entry`, `name`, `body_size`, and the
list of `ranges` after the change.

## Implemented Phase 7: Unions and Remaining Data Layout

### Unions

- `create_union(name, category?)`.
- `delete_union(path)`.
- `add_union_field(path, type_path, field_name?, length?, comment?)`.
- `rename_union_field(path, new_name, ordinal?|field_name?)`.
- `set_union_field_type(path, type_path, ordinal?|field_name?, length?, comment?)`.
- `delete_union_field(path, ordinal?|field_name?)`.

### Data Layout at an Address

- `clear_data(address, length?, clear_context?)` — clear code units. If
  `length` is omitted, clears the single defined data item at or containing the
  address.
- `create_string(address, encoding?, length?, null_terminated?)` — apply a
  string. Supported encodings: `ascii`, `utf8`, `utf16`. Null-terminated by
  default. If `null_terminated` is `0`, a length must be supplied.
- `create_array(address, element_type_path, count)` — apply a fixed-count array
  of an existing data type. Clears overlapping code units before applying.

## Implemented Phase 8: Analysis Workflow Control and Undefined-Code Discovery

### Analyzer Controls

- `list_analyzers(applicable?, offset?, limit?)` — enumerate registered
  analyzers (default: only those applicable to the current program). Each
  entry returns name, description, analyzer type, priority, default and
  current enable state, `can_analyze`, `supports_one_time`, and
  `is_prototype`.
- `get_analyzer_options(name)` — return per-analyzer options as
  `{name, type, value, default, description, is_default}` along with the
  current enable flag.
- `set_analyzer_option(name, option?, value)` — set an arbitrary analyzer
  option (uses Ghidra's `OptionType.convertStringToObject`). When `option`
  is omitted, sets the analyzer's enable flag itself.
- `enable_analyzer(name)` / `disable_analyzer(name)` — convenience
  wrappers for toggling the enable flag.

### Targeted Analysis

- `run_analyzer(name, start?, end?, function_address?, function_name?)` —
  schedule a single analyzer (`AutoAnalysisManager.scheduleOneTimeAnalysis`)
  over the supplied address set and start analysis. The range defaults to
  full program memory; a function range can be specified by entry or name.
  The analyzer must support one-time analysis.
- `analyze_range(start?, end?, function_address?, function_name?)` —
  re-analyze the supplied range (`reAnalyzeAll` + `startAnalysis`).
- `analyze_function(function_address|function_name|address)` — re-analyze
  the body of one function.
- `get_analysis_status` — return `{analyzing, total_time_ms, has_messages,
  message_log, timed_tasks}`.
- `get_analysis_log` — return `{has_messages, status, text, task_times}`
  pulled from the AutoAnalysisManager message log.

### Undefined-Code Discovery

- `list_undefined_ranges(start?, end?, min_length?, offset?, limit?)` —
  return initialized-memory ranges with no defined code or data, optionally
  scoped to a sub-range and filtered by length. Each item includes
  `start`, `end`, `length`, `block`, and `executable`.
- `list_executable_undefined_ranges(...)` — same, restricted to executable
  memory blocks.
- `find_possible_functions(start?, end?, alignment?, max_scan?, offset?, limit?)`
  — scan undefined executable ranges and return addresses where Ghidra's
  `PseudoDisassembler.isValidSubroutine` reports a plausible function start.
  `alignment` defaults to the architecture's instruction alignment;
  `max_scan` caps candidate starts inspected (response notes whether the
  scan was truncated).

## Implemented Phase 9: Pointer/Jump Tables and Raw String Discovery

### `find_pointer_tables(start?, end?, min_entries?, alignment?, executable_targets?, max_scan?, offset?, limit?)`

Scan undefined initialized memory for runs of pointer-sized values whose
decoded value points into loaded memory. Each candidate returns its
`start`, `entry_size`, `entry_count`, `byte_length`, list of `targets`,
and containing `block`. Set `executable_targets=true` to require targets
to land in an executable memory block (useful for vtable / jump-table
discovery).

### `find_jump_tables(function_address?|function_name?|start?, end?, min_entries?, offset?, limit?)`

Look at computed jump instructions and report ones whose attached
references include at least `min_entries` flow destinations. Each entry
returns the source instruction address, mnemonic, containing function,
the referenced data table address (when distinct), and the list of
destinations. Scope may be one function, an address range, or the whole
program.

### `find_ascii_strings(start?, end?, min_length?, undefined_only?, max_scan?, offset?, limit?)`

### `find_utf16_strings(...)`

Scan memory for runs of printable characters (ASCII or UTF-16). By
default only undefined memory ranges are scanned so already-defined
strings are not re-reported. Each hit returns `address`, `length`
(characters), `encoding`, `byte_length`, a preview `text`, and the
containing memory `block`. The response carries `scanned_bytes` and a
`truncated` flag so callers know whether to extend `max_scan`.

## Implemented Phase 10: Program Lifecycle

- `list_open_programs` — enumerate all programs currently held by the
  Ghidra `ProgramManager`. Each entry returns name, project path,
  language, compiler spec, image base, function count, `changed` flag,
  `read_only` flag, and a `current` flag for the active program.
- `select_program(name?, path?)` — make a named/path-identified open
  program the current program.
- `save_program(name?, path?)` — save the named program (or the current
  program) back to its `DomainFile` and report the cleared `changed`
  flag on success.
- `close_program(name?, path?, ignore_changes?)` — close a program from
  the tool. Refuses unsaved changes unless `ignore_changes=true`.
- `import_file(path, folder?, open?)` — import a binary from disk via
  Ghidra's `AutoImporter`. Places the result in the named project folder
  (default: root) and optionally opens it in the active tool.
- `open_program(path)` — open a program already stored in the active
  project, identified by its `DomainFile` path (e.g. `/MyBinary`).

All endpoints return structured envelopes and validate parameters before
touching project state.

## Implemented Phase 11: Exports

- `export_bytes(start, end?|length?, path?)` — read up to 50 MB from
  program memory. With `path` writes raw bytes to disk; without `path`
  returns the contents hex-encoded.
- `export_patched_binary(path, initialized_only?)` — concatenate memory
  blocks to a flat file on disk (initialized-only by default).
- `export_symbols(format?, path?, user_only?)` — dump all symbols as
  JSON, CSV, or text. `user_only=true` keeps only user-defined symbols.
- `export_function_map(format?, path?)` — emit entry, name, namespace,
  body size, and signature for every function in JSON/CSV/text form.
- `export_c_header(path?, category?)` — produce a header-like dump of
  every struct, union, enum, and typedef. `category` filters by category
  path substring.
- `export_analysis_report(format?, path?)` — summarize the program:
  function counts (user-named vs default), user-defined symbol count,
  comment count, type counts (struct/union/enum/typedef), patch history
  size, and undefined-executable byte count. JSON or text.

Each export either returns the rendered body inline or writes to the
caller-supplied `path` and returns the absolute filename.

## Implemented Phase 12: Patch History and Patch Helpers

- `assemble_instruction(address, instruction)` — assemble using
  Ghidra's `Assemblers` API without writing to memory. Returns the
  encoded bytes and length.
- `patch_instruction(address, instruction, rationale?, dry_run?)` —
  assemble, validate, and write the instruction at `address`. Records a
  patch entry containing the original and new bytes.
- `nop_range(start, end?|length?, rationale?, dry_run?)` — overwrite a
  range with the architecture's NOP encoding (uses the assembler when
  available, falls back to `0x90`). Length must be a multiple of the
  single-NOP length.
- `patch_call_target(address, target, rationale?, dry_run?)` and
  `patch_branch_target(address, target, rationale?, dry_run?)` —
  re-assemble the call/jump at `address` so that it targets `target`.
  Fails if the new encoding would not fit in the original slot; pads
  with NOPs when shorter.
- `create_patch_record(address, new_bytes, original_bytes?, rationale?)`
  — manually record a patch (hex strings for the bytes). Useful for
  byte changes applied outside `patch_instruction`/`nop_range`.
- `list_patches(active_only?, offset?, limit?)` — paginated patch
  history (`id`, `address`, `original_bytes`, `new_bytes`, `length`,
  `rationale`, `timestamp`, `reverted`).
- `revert_patch(id)` — restore the original bytes for the named patch
  and mark it `reverted=true`.

All write endpoints support `dry_run=true`, which returns the proposed
bytes without modifying memory.

## Implemented Phase 13: Project Lifecycle, Async Analysis, Navigation, Bring-Up

### Project Lifecycle

- `project_info` — name, locator, file count, active tool, current
  program for the active Ghidra project.
- `open_project(path)` — open a Ghidra project by its on-disk path
  (`.gpr` file or project directory). Closes the currently active
  project first; uses `ProjectManager.openProject` and
  `FrontEndTool.setActiveProject`.
- `close_project(save?)` — close the active project (saves first by
  default).
- `create_project(path, name?)` — create a new project at the given
  directory and make it active.
- `save_project` — flush project state (recent files / folder index).

### Project File Enumeration

- `list_project_files(folder?, recursive?)` — enumerate `DomainFile`s
  under `folder` in the active project (default `/`, recursive). Each
  entry returns name, path, content type, domain object class,
  read-only/versioned flags.
- `project_file_exists(path)` — test whether a project path exists.
- `delete_project_file(path)` — delete a `DomainFile`.

### Loader / Language Enumeration

- `list_loaders` — installed Ghidra loaders (importer classes). Each
  entry exposes three fields: `name` (Loader.getName() display name),
  `loader_name` (simple class name — this is the value to pass as
  `loader_name` to `import_file`/`bring_up`, since
  `LoaderService.getLoaderClassByName` matches on simple class name,
  not display name), and `class` (fully-qualified class name).
  `import_file`'s `loader_name` accepts any of the three forms.
- `list_languages(processor?, language_id?)` — installed languages,
  filtered by processor (e.g. `ARM`) or exact language ID.
- `list_compiler_specs(language_id)` — compiler specs compatible with
  the given language.

### Import With Loader Override

`import_file` was rewritten to use `AutoImporter` directly (no
reflection), and now accepts:

- `loader_name` — force a specific loader class (e.g.
  `GameBoyAdvanceLoader`, `BinaryLoader`).
- `language_id` — force a language for raw-binary loads.
- `compiler_spec` — compiler spec ID (defaults to the language's
  default).
- `image_base` — set after the import succeeds.
- `loader_options` — `key1=value1,key2=value2` shorthand or a JSON
  object string of loader-specific options, passed through as a
  `List<Pair<String,String>>` to the typed importer.

Routes to one of:
`importByUsingBestGuess`,
`importByUsingSpecificLoaderClass`,
`importByLookingForLcs`, or
`importByUsingSpecificLoaderClassAndLcs` depending on which overrides
are supplied.

### Async Analysis

- `start_analysis(reanalyze?)` — kick off auto-analysis on the current
  program in a background thread, return a `job_id` immediately. Each
  job wraps a custom `TaskMonitor` (`ProgressTaskMonitor`) that
  captures `message`, `progress`, and `max` so HTTP callers can poll
  progress without blocking the Ghidra EDT.
- `analysis_progress(job_id?)` — return one job (by id) or all jobs.
  Each record carries `state` (`queued|running|done|cancelled|error`),
  `percent`, `current_task`, `elapsed_ms`,
  `function_count_start`/`function_count`, and any `error`.
- `cancel_analysis(job_id)` — set the job's monitor cancelled and drop
  queued analyzer tasks (`AutoAnalysisManager.cancelQueuedTasks`).

### Readiness, Navigation

- `ready` — single-shot summary: project state, tool kind, current
  program (name/path/language/image base/function count/analyzing),
  open programs, and any active analysis jobs. Lets a client decide
  its next action without 5 round-trips.
- `goto(address)` — move the Ghidra listing cursor to `address`
  (uses `GoToService` when available, falls back to
  `CodeViewerService.goTo`).
- `select_range(start, end)` — select `[start, end]` in the listing
  and goto `start`.

### GBA Memory Map

- `ensure_gba_memory_map(overwrite?)` — create the canonical GBA
  memory map as uninitialized blocks with correct R/W/X permissions:
  BIOS (`0x00000000`/`0x4000`, R/X), EWRAM (`0x02000000`/`0x40000`,
  RW/X), IWRAM (`0x03000000`/`0x8000`, RW/X), IO
  (`0x04000000`/`0x400`, RW), Palette, VRAM, OAM, ROM mirror
  (`0x0A000000`/`0x2000000`, R/X), SRAM (`0x0E000000`/`0x10000`, RW).
  Skips regions that already have a block; with `overwrite=true`
  drops and recreates them.

### One-Shot Bring-Up

- `bring_up(rom_path, project_path?, loader_name?, language_id?,
  compiler_spec?, image_base?, loader_options?, folder?, ensure_gba?,
  analyze?, wait_ms?, seed_addresses?, seed_image_base?)` — open the
  project (if `project_path` is given), import the ROM if not already
  in the project (or open the existing program), optionally ensure the
  GBA memory map, optionally seed disassembly, start analysis
  asynchronously. Raw-binary loaders don't emit entry points, so the
  first analysis pass finds 0 functions; pass
  `seed_addresses="0x08000000,0x080000C0,..."` (comma-separated) and/or
  `seed_image_base=true` to disassemble at those locations BEFORE
  analysis runs, giving the analyzer something to follow. Reported
  back as `disassemble_seeds` in the response. With `wait_ms>0`, blocks
  up to that many milliseconds waiting for analysis to complete;
  otherwise returns immediately with `job_id` to poll via
  `analysis_progress`.

## Implemented Phase 14: ARM/Thumb Constant-Pool Fixes

Two ARM/Thumb behaviors that the stock Ghidra analyzers leave on the
floor even when fully enabled, exposed as targeted workarounds the
agent can invoke when it spots the problem.

### `propagate_ldr_pc_refs(start?, end?, function_address?|function_name?, dry_run?, max_scan?, limit?, seed_pointer_refs?)`

Iterates LDR-family instructions (`ldr`, `ldrh`, `ldrsh`, `ldrb`,
`ldrsb`, `ldrd`, `vldr`, plus `.w` variants) in the requested scope
and, for each `[pc, #imm]` literal operand whose computed target has
no existing reference, adds a `READ` memory reference from the
instruction to the literal address with `SourceType.ANALYSIS`.

- Honors the current `TMode` at each instruction: ARM uses `PC+8`,
  Thumb uses `(PC+4) & ~3`.
- Falls back to SLEIGH-resolved absolute literal operands when the
  decoded operand is already an `Address` object.
- Scope: a function (by address or name), an inclusive `[start, end]`
  range, or the entire program.
- `dry_run=true` reports what would be added without writing.

When `seed_pointer_refs=true` (default), the same pass also reads the
pointer-sized word at each constant-pool slot. If that value resolves
to an address contained in loaded memory (e.g. an EWRAM pointer like
`gSaveBlock2Ptr=0x03005390`, an IWRAM pointer, or a ROM pointer), the
pass adds a `DATA` `SourceType.ANALYSIS` reference both from the LDR
instruction and from the constant-pool slot to that pointer target.
The instruction-side edge means `xrefs_to(<pointer_target>)`
enumerates every function that loads the pointer in a single query —
"every function that touches `gSaveBlock2Ptr`" without walking the
constant-pool intermediate. Pointer seeding also runs for LDR refs
that were already present, so re-running on a previously-propagated
program backfills the pointer-target edges without re-adding the LDR
ref itself.

Returns `scanned_instructions`, `ldr_pc_candidates`, `added_count`,
`already_present_count`, `seed_pointer_refs`, `pointer_candidates`,
`pointer_refs_added_from_instr`, `pointer_refs_added_from_pool`, and
the list of LDR additions (each with `from`, `to`, `operand`,
`mnemonic`, `thumb`, `pointer_value`, and — when a pointer target was
seeded — `pointer_target`, `pointer_ref_from_instr_seeded`,
`pointer_ref_from_pool_seeded`).

Workaround for: PC-relative `ldr [pc, #imm]` references not being
propagated to the Reference Manager even with every reference
analyzer enabled, and the related gap where the constant-pool slot
itself holds an EWRAM/IWRAM/ROM pointer whose target gets no xref
edges seeded by stock analysis.

### `create_thumb_function_from_pointer(pointer_address, name?, force_mode?, create_pointer_data?, add_reference?)`

Reads the pointer-sized word at `pointer_address` (the constant-pool
slot), masks the Thumb bit off the low bit of the value, sets
`TMode=1` (Thumb) or `TMode=0` (ARM) at the target, clears any
wrong-mode disassembly already at the target, then disassembles and
creates a function at the target. Optionally renames the new
function, applies `pointer` data at `pointer_address`, and adds a
data reference from the pointer slot to the target.

- `force_mode` overrides Thumb/ARM auto-detection (`"thumb"` /
  `"arm"`).
- Returns the resolved target, the detected mode, the function name,
  and a `status` summary of each step.

Workaround for: THUMB-mode functions created from constant-pool
function pointers defaulting to ARM disassembly.

### `scan_thumb_pointer_table(start, end?, max_entries?, require_executable?, stop_on_invalid?, create_functions?)`

Walks `[start, end]` (or up to `max_entries` pointer-sized words from
`start`) as a table of function pointers and calls
`create_thumb_function_from_pointer` on each entry. By default stops
on the first entry that is zero, points outside loaded memory, or
(with `require_executable=true`) points into a non-executable block.
Returns per-entry results and counts of `created` / `skipped`.

## Implemented Phase 15: Agent Self-Discovery Hints

Agents often "ping" the MCP server to confirm it is reachable and
then stop short of capabilities they actually have. Two endpoints now
surface short, context-aware reminders so the agent doesn't have to
ask the user for things it can do itself.

### `agent_hints`

Returns a `hints` list with:

- Always: a reminder that the agent can import binaries on its own
  (`import_file(path)`, `open_program(project_path)`,
  `bring_up(rom_path, ...)`) and switch between open programs
  (`list_open_programs`, `select_program`).
- Always: a reminder that the `Scalar Operand References` analyzer is
  **disabled by default** in stock Ghidra and that enabling it on
  dense binaries can surface 28,000+ additional function references.
  Includes the exact command — `enable_analyzer(name="Scalar Operand
  References")` followed by `analyze()` (or `analyze_range(start,
  end)` for a scoped re-run). ELF programs get an additional hint for
  `ELF Scalar Operand References`.
- When the current program is ARM/Thumb: a reminder that
  `propagate_ldr_pc_refs`, `create_thumb_function_from_pointer`, and
  `scan_thumb_pointer_table` exist for the constant-pool issues
  Ghidra leaves on the floor.
- When no project / no program is loaded: explicit pointers to
  `open_project`, `create_project`, `list_project_files`,
  `import_file`, and `open_program`.

The same list is also embedded in the `/ready` response as
`agent_hints` and appended to the plaintext `/program_info` output as
`agent_hint=...` lines, so agents that ping any of those endpoints
discover the same guidance without an extra round-trip.

## Implemented Phase 16: Discovery Aliases and Bulk Function Seeding

### `list_endpoints` (aliases: `/endpoints`, `/help`, `/list_methods`)

Returns a newline-separated list of every HTTP path the plugin
currently exposes. Lets an agent enumerate available functionality in
one round-trip instead of guessing endpoint names. `/endpoints`,
`/list_endpoints`, `/help`, and `/list_methods` all resolve to the
same handler, so an agent probing common discovery names lands on the
catalogue immediately.

### `count_functions`

Returns the total number of functions in the current program as a
small JSON envelope (`{ok, data: {count}, error}`). Cheap, single-
purpose alternative to paging `/methods` or parsing `/program_info`.

### `get_program_info`

Alias for `program_info`. Same plaintext output (language, compiler,
image base, address range, function count, agent hints). Provided
because `get_*` is the natural verb agents reach for first.

### `list_memory_blocks`

JSON listing of every memory block with `name`, `start`, `end`,
`size`, `read`, `write`, `execute`, `initialized`, `overlay`, `type`,
and (when set) `comment`. Paginated via `offset`/`limit`. Richer than
the plaintext `/segments` endpoint — agents can filter on
permissions/initialization flags without reparsing text.

### `seed_functions_in_range(start, end, mode?, detect_thumb_no_lr?, max_seeds?, dry_run?, preview_limit?)`

Walk an address range and create a function at every position that
looks like an ARM/Thumb function prologue (`push {…}`). Built to
speed up bring-up of dense ARM/Thumb ROMs (e.g. GBA) where Ghidra's
auto-analysis stops at ~1.6k functions on a fresh import even though
the same binary yields 28k+ functions in a longer manual session.

Pattern matches in undefined initialized executable memory within
`[start, end]`:

- Thumb `push {…, lr}` (`0xB5xx`, 2-byte aligned)
- Thumb `push {…}` (`0xB4xx`, 2-byte aligned) — opt-in via
  `detect_thumb_no_lr=true` (noisier; many sequences with `0xB4` as
  the second byte are not function prologues)
- ARM `stmdb sp!, {…}` (`0xE92Dxxxx`, 4-byte aligned)

For each candidate the endpoint, in a single transaction:

1. Sets `TMode` at the candidate address (1 for Thumb, 0 for ARM).
2. Runs Ghidra's `DisassembleCommand` at the address.
3. Runs `CreateFunctionCmd` to create the function — Ghidra then
   walks the flow to discover the function body.

Skips addresses that already host a function or any existing
instruction (which may be in the wrong mode). `mode` selects which
prologues to consider (`"thumb"`, `"arm"`, or `"both"`; default
`"thumb"`). `max_seeds` caps how many functions are created in this
call. `dry_run=true` reports candidate counts and a sample without
writing.

Returns JSON with `scanned_bytes`, `thumb_candidates`,
`arm_candidates`, `created_count`, `failed_count`, and small
`created_preview` / `failed_preview` lists capped by `preview_limit`.

## Implemented Phase 17: Unified Param Handling and Fixed-Stride String Tables

### Unified GET/POST parameter parsing

`parseAllParams(exchange)` is the new canonical body-and-query parser:
it pulls form-encoded `key=value` pairs from both the URL query string
and the request body and merges them (body wins on collisions). The
older `parseQueryParams` and `parsePostParams` now both delegate to it,
so every endpoint accepts params from either source transparently.

Removes the historical inconsistency where some endpoints accepted only
GET query params (e.g. `decompile_function`) and others required POST
form bodies (e.g. `disassemble`, `create_function`, `set_tmode`).
Clients no longer have to know — or guess — which verb a route expects;
both work everywhere.

### `string_table_at(base, stride, count, encoding?, trim_null?, apply?, preview_limit?)`

Extract a flat fixed-stride C-string table from program memory. Useful
when names (species, moves, items, …) live in a tightly-packed array of
fixed-width null-padded strings: with the stride and base already
known, this is much more precise than byte-level string scanning.

- `base` — start address (required).
- `stride` — bytes per entry (required, `> 0`). Total `stride*count`
  capped at 16 MiB.
- `count` — number of entries (required, `> 0`).
- `encoding` — `ascii` (default), `utf8`, `latin1`, or `raw` (returns
  per-entry hex bytes).
- `trim_null` — trim each entry at the first `0x00` (default `true`).
- `apply` — when `true`, create string `Data` at every entry in a
  single transaction (terminated string when a NUL is present,
  fixed-length otherwise). Clears any conflicting code units inside
  each entry's stride first. Default `false` (read-only).
- `preview_limit` — cap on entries embedded in the response (default
  `1024`).

Returns `{base, stride, count, readable_entries, encoding, entries:
[{index, address, text|raw_hex, length}], truncated?, applied_count?,
apply_errors?}`. When the underlying memory read returns fewer bytes
than requested (end of block), `readable_entries` reflects what was
actually decoded.
