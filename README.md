# GhidraMCP

GhidraMCP connects an MCP client to a live Ghidra session. The Ghidra extension starts a local HTTP server inside Ghidra, and `bridge_mcp_ghidra.py` exposes that server as MCP tools over `stdio` or SSE.

This is useful for assisted reverse engineering: an MCP client can inspect functions, decompile code, follow references, read and patch memory, rename symbols, add comments, create functions/data, and adjust program memory layout without requiring every action to be performed manually in the Ghidra UI.

## Features

- Program overview: language/compiler info, image base, memory range, and function count.
- Listings: functions, methods, classes, namespaces, imports, exports, segments, data items, and strings.
- Address, instruction, data, symbol, comment, bookmark, and function inspection: structured address summaries, instruction details/listings, defined data details, function details, variable listings, symbol/comment/bookmark queries, lookup by name or address, decompile by name or address, disassemble function bodies, and inspect current GUI selection.
- Reference inspection: xrefs to/from addresses, xrefs to named functions, and structured unified references.
- Symbol, type, function, parameter, and comment edits: rename functions/data/variables, set function prototypes, set return types/calling conventions/function flags, edit parameters and stack variables, set local variable types, add comments, create labels/namespaces, and apply data types.
- Memory and analysis edits: read bytes, write bytes, find byte patterns, clear listing ranges, force disassembly, create/delete functions, create labels, create simple data, rerun analysis, set image base, manage memory blocks, and set ARM Thumb/ARM `TMode`.

## Requirements

- Ghidra 12.2
- Java 21
- Maven
- Python 3.10 or newer
- Python packages from `requirements.txt`

## Build The Ghidra Extension

Copy these Ghidra jars into `lib/`:

- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/FileSystem/lib/FileSystem.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`

Then build:

```sh
mvn clean package
```

The extension zip is written to:

```text
target/GhidraMCP-1.0-SNAPSHOT.zip
```

The build also creates `target/GhidraMCP.jar`. Build artifacts and local Ghidra jars are ignored by Git.

## Install In Ghidra

1. Open Ghidra.
2. Select `File` -> `Install Extensions`.
3. Click the `+` button.
4. Select `target/GhidraMCP-1.0-SNAPSHOT.zip`.
5. Restart Ghidra.
6. Enable `GhidraMCPPlugin` from `File` -> `Configure` -> `Developer`.
7. Optional: change the HTTP server port in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`.

The plugin listens on `http://127.0.0.1:8080/` by default.

## Run The MCP Bridge

Install Python dependencies:

```sh
python -m pip install -r requirements.txt
```

For MCP clients that launch tools over `stdio`, point the client at:

```sh
python /absolute/path/to/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

For SSE:

```sh
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Claude Desktop example:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/absolute/path/to/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

## MCP Tools

Read and navigation tools:

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
- `get_xrefs_via_pool`
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

Write and analysis tools:

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

## Roadmap

These are the next features that would make the MCP more useful for autonomous reverse engineering.

1. Add richer read primitives.
   - `get_address_info`, `get_instruction_at`, `get_instructions`, `get_data_at`, `get_function_details`, and `list_function_variables` are available as structured JSON tools.
   - `list_symbols`, `search_symbols`, `get_symbol`, `list_comments`, `list_bookmarks`, and `get_references` are available as structured JSON tools.

2. Add better type-system access.
   - `list_data_types`, `search_data_types`, `get_data_type`, `get_struct_layout`, `get_enum_values`, and `get_typedef_target` are available as structured JSON tools.
   - Full data type creation and field-editing writes remain to be added.

3. Add missing write actions for normal RE annotation.
   - Create/delete references, create stack/external references, and set primary references.
   - Set/delete labels with namespace and primary-symbol control, and create/rename namespaces.
   - Set repeatable, plate, pre, post, and EOL comments explicitly.
   - Set function calling convention, return type, parameter names, parameter types/storage/order, no-return/inline/varargs flags, comments, and thunk targets.
   - Create stack variables and rename/retype parameters separately from locals.

4. Add type creation and data layout writes.
   - Create structs, enums, typedefs, arrays, pointers, and function-definition data types.
   - Add, rename, delete, and retype structure fields.
   - Apply any existing data type by full category path, not only simple byte/word/dword/qword/string types.
   - Unions and explicit string creation remain to be added.

5. Add analysis workflow controls.
   - Enable/disable analyzers and run a named analyzer or address set.
   - Create functions over explicit address ranges and repair function bodies.
   - Discover undefined executable ranges, suspicious pointer tables, jump tables, and likely function starts.
   - Expose analyzer messages/errors so failures are visible to the MCP client.

6. Add import/export and project operations.
   - Open/import a binary into the active project from a path.
   - Save the current program.
   - Export bytes, patched binaries, symbols, maps, C headers, and analysis summaries.
   - Manage multiple open programs and select the active program.

7. Improve safety and reliability.
   - Add optional dry-run parameters for destructive operations.
   - Return structured JSON instead of newline-delimited text for complex results.
   - Include address validation and clearer error messages.
   - Add integration tests for each HTTP endpoint and MCP wrapper.
