# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def get_address_info(address: str) -> str:
    """
    Return a structured JSON summary of the code, data, symbols, comments,
    memory block, bytes, and references at an address.
    """
    return "\n".join(safe_get("get_address_info", {"address": address}))

@mcp.tool()
def get_instruction_at(address: str) -> str:
    """
    Return structured JSON details for the instruction at or containing address.
    Includes mnemonic, operands, bytes, flow, pcode, containing function, and comments.
    """
    return "\n".join(safe_get("get_instruction_at", {"address": address}))

@mcp.tool()
def get_instructions(start: str, end: str = "", limit: int = 100) -> str:
    """
    Return a structured JSON instruction listing starting at `start`.
    Optionally stops at `end`; `limit` is capped by the Ghidra extension.
    """
    params = {"start": start, "limit": limit}
    if end:
        params["end"] = end
    return "\n".join(safe_get("get_instructions", params))

@mcp.tool()
def get_data_at(address: str) -> str:
    """
    Return structured JSON details for defined data at or containing address.
    Includes data type path, value, raw bytes, labels, parent, and components.
    """
    return "\n".join(safe_get("get_data_at", {"address": address}))

@mcp.tool()
def get_function_details(address: str = "", name: str = "") -> str:
    """
    Return structured JSON details for a function by address or exact name.
    Includes signature, body ranges, variables, flags, callers, callees,
    referenced data/strings, comments, and outbound references.
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("get_function_details", params))

@mcp.tool()
def list_function_variables(address: str = "", name: str = "") -> str:
    """
    Return decompiler variables for a function by address or exact name as JSON.
    Includes name, data type, storage, size, source, parameter/global flags,
    representative varnode, and varnodes.
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("list_function_variables", params))

@mcp.tool()
def list_symbols(query: str = "", type: str = "", source: str = "",
                 start: str = "", end: str = "", block: str = "",
                 offset: int = 0, limit: int = 100) -> str:
    """
    List symbols as structured JSON with optional name, type, source, range, and block filters.
    """
    params = {"offset": offset, "limit": limit}
    for key, value in {
        "query": query, "type": type, "source": source,
        "start": start, "end": end, "block": block,
    }.items():
        if value:
            params[key] = value
    return "\n".join(safe_get("list_symbols", params))

@mcp.tool()
def search_symbols(query: str, type: str = "", source: str = "",
                   offset: int = 0, limit: int = 100) -> str:
    """
    Search symbols by name substring and return structured JSON results.
    """
    params = {"query": query, "offset": offset, "limit": limit}
    if type:
        params["type"] = type
    if source:
        params["source"] = source
    return "\n".join(safe_get("search_symbols", params))

@mcp.tool()
def get_symbol(address: str = "", name: str = "") -> str:
    """
    Return symbol details by address and/or name, including primary symbol details.
    """
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    return "\n".join(safe_get("get_symbol", params))

@mcp.tool()
def list_comments(start: str = "", end: str = "", function_address: str = "",
                  function_name: str = "", offset: int = 0, limit: int = 100) -> str:
    """
    List plate, pre, post, EOL, and repeatable comments in a range or function.
    """
    params = {"offset": offset, "limit": limit}
    for key, value in {
        "start": start, "end": end,
        "function_address": function_address, "function_name": function_name,
    }.items():
        if value:
            params[key] = value
    return "\n".join(safe_get("list_comments", params))

@mcp.tool()
def list_bookmarks(type: str = "", category: str = "",
                   offset: int = 0, limit: int = 100) -> str:
    """
    List Ghidra bookmarks as structured JSON with optional type/category filters.
    """
    params = {"offset": offset, "limit": limit}
    if type:
        params["type"] = type
    if category:
        params["category"] = category
    return "\n".join(safe_get("list_bookmarks", params))

@mcp.tool()
def get_references(address: str = "", direction: str = "both",
                   function_address: str = "", function_name: str = "",
                   offset: int = 0, limit: int = 100) -> str:
    """
    Return structured references to/from an address or function.
    direction may be 'to', 'from', or 'both'.
    """
    params = {"direction": direction, "offset": offset, "limit": limit}
    for key, value in {
        "address": address,
        "function_address": function_address,
        "function_name": function_name,
    }.items():
        if value:
            params[key] = value
    return "\n".join(safe_get("get_references", params))

@mcp.tool()
def set_comment(address: str, type: str = "eol", text: str = "",
                mode: str = "replace") -> str:
    """
    Set a comment at address. type may be plate, pre, post, eol, or repeatable.
    mode may be replace, append, prepend, or clear.
    """
    return safe_post("set_comment", {
        "address": address, "type": type, "text": text, "mode": mode,
    })

@mcp.tool()
def set_label(address: str, name: str, namespace: str = "",
              primary: str = "0", source: str = "user_defined") -> str:
    """
    Create or update a label at address with optional namespace and primary-symbol control.
    """
    return safe_post("set_label", {
        "address": address, "name": name, "namespace": namespace,
        "primary": primary, "source": source,
    })

@mcp.tool()
def delete_label(address: str, name: str, namespace: str = "") -> str:
    """
    Delete a specific label at address.
    """
    return safe_post("delete_label", {
        "address": address, "name": name, "namespace": namespace,
    })

@mcp.tool()
def set_primary_symbol(address: str, name: str) -> str:
    """
    Set one symbol at address as the primary symbol.
    """
    return safe_post("set_primary_symbol", {"address": address, "name": name})

@mcp.tool()
def create_namespace(name: str, parent: str = "", source: str = "user_defined") -> str:
    """
    Create a namespace under the optional parent namespace.
    """
    return safe_post("create_namespace", {"name": name, "parent": parent, "source": source})

@mcp.tool()
def rename_namespace(old_name: str, new_name: str, source: str = "user_defined") -> str:
    """
    Rename a namespace by full namespace path.
    """
    return safe_post("rename_namespace", {
        "old_name": old_name, "new_name": new_name, "source": source,
    })

@mcp.tool()
def create_reference(from_address: str, to_address: str, ref_type: str = "data",
                     operand_index: int = -1, source: str = "user_defined") -> str:
    """
    Create a memory reference from one address to another.
    """
    return safe_post("create_reference", {
        "from_address": from_address, "to_address": to_address,
        "ref_type": ref_type, "operand_index": operand_index, "source": source,
    })

@mcp.tool()
def delete_reference(from_address: str, to_address: str, operand_index: int = -1) -> str:
    """
    Delete a reference by from address, to address, and operand index.
    """
    return safe_post("delete_reference", {
        "from_address": from_address, "to_address": to_address,
        "operand_index": operand_index,
    })

@mcp.tool()
def set_reference_primary(from_address: str, to_address: str,
                          operand_index: int = -1, primary: str = "1") -> str:
    """
    Set or clear the primary flag for a reference.
    """
    return safe_post("set_reference_primary", {
        "from_address": from_address, "to_address": to_address,
        "operand_index": operand_index, "primary": primary,
    })

@mcp.tool()
def create_memory_reference(from_address: str, to_address: str, ref_type: str = "data",
                            operand_index: int = -1, source: str = "user_defined") -> str:
    """
    Create a memory reference. Alias for create_reference.
    """
    return create_reference(from_address, to_address, ref_type, operand_index, source)

@mcp.tool()
def create_stack_reference(from_address: str, stack_offset: int, ref_type: str = "read",
                           operand_index: int = -1, source: str = "user_defined") -> str:
    """
    Create a stack reference from an instruction operand to a stack offset.
    """
    return safe_post("create_stack_reference", {
        "from_address": from_address, "stack_offset": stack_offset,
        "ref_type": ref_type, "operand_index": operand_index, "source": source,
    })

@mcp.tool()
def create_external_reference(from_address: str, library: str, label: str,
                              external_address: str = "", ref_type: str = "external",
                              operand_index: int = -1, source: str = "user_defined") -> str:
    """
    Create an external reference from an address to a library symbol.
    """
    return safe_post("create_external_reference", {
        "from_address": from_address, "library": library, "label": label,
        "external_address": external_address, "ref_type": ref_type,
        "operand_index": operand_index, "source": source,
    })

@mcp.tool()
def list_data_types(query: str = "", kind: str = "",
                    offset: int = 0, limit: int = 100) -> str:
    """
    List data types as structured JSON, optionally filtered by path substring and kind.
    """
    params = {"offset": offset, "limit": limit}
    if query:
        params["query"] = query
    if kind:
        params["kind"] = kind
    return "\n".join(safe_get("list_data_types", params))

@mcp.tool()
def search_data_types(query: str, kind: str = "",
                      offset: int = 0, limit: int = 100) -> str:
    """
    Search data types by path/name substring.
    """
    return list_data_types(query, kind, offset, limit)

@mcp.tool()
def get_data_type(path: str) -> str:
    """
    Return details for a data type by full path or name.
    """
    return "\n".join(safe_get("get_data_type", {"path": path}))

@mcp.tool()
def get_struct_layout(path: str) -> str:
    """
    Return structure fields, offsets, lengths, packing, and alignment as JSON.
    """
    return "\n".join(safe_get("get_struct_layout", {"path": path}))

@mcp.tool()
def get_enum_values(path: str) -> str:
    """
    Return enum values and comments as JSON.
    """
    return "\n".join(safe_get("get_enum_values", {"path": path}))

@mcp.tool()
def get_typedef_target(path: str) -> str:
    """
    Return typedef target and base target as JSON.
    """
    return "\n".join(safe_get("get_typedef_target", {"path": path}))

@mcp.tool()
def apply_data_type(address: str, type_path: str, length: int = -1,
                    clear_mode: str = "conflicts") -> str:
    """
    Apply an existing data type by path/name at address.
    clear_mode may be conflicts or none.
    """
    data = {"address": address, "type_path": type_path, "clear_mode": clear_mode}
    if length > 0:
        data["length"] = length
    return safe_post("apply_data_type", data)

@mcp.tool()
def create_struct(name: str, category: str = "/", length: int = 0) -> str:
    """
    Create a structure data type.
    """
    return safe_post("create_struct", {"name": name, "category": category, "length": length})

@mcp.tool()
def delete_struct(path: str) -> str:
    """
    Delete a structure data type by path/name.
    """
    return safe_post("delete_struct", {"path": path})

@mcp.tool()
def rename_data_type(path: str, new_name: str, category: str = "") -> str:
    """
    Rename or move a data type.
    """
    return safe_post("rename_data_type", {"path": path, "new_name": new_name, "category": category})

@mcp.tool()
def add_struct_field(path: str, type_path: str, field_name: str = "",
                     length: int = -1, comment: str = "") -> str:
    """
    Add a field to the end of a structure.
    """
    data = {"path": path, "type_path": type_path, "field_name": field_name, "comment": comment}
    if length > 0:
        data["length"] = length
    return safe_post("add_struct_field", data)

@mcp.tool()
def rename_struct_field(path: str, new_name: str,
                        ordinal: int = -1, offset: int = -2147483648,
                        field_name: str = "") -> str:
    """
    Rename a structure field by ordinal, offset, or current field name.
    """
    data = {"path": path, "new_name": new_name}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if offset != -2147483648:
        data["offset"] = offset
    if field_name:
        data["field_name"] = field_name
    return safe_post("rename_struct_field", data)

@mcp.tool()
def set_struct_field_type(path: str, type_path: str,
                          ordinal: int = -1, offset: int = -2147483648,
                          field_name: str = "", length: int = -1,
                          comment: str = "") -> str:
    """
    Replace a structure field's data type by ordinal, offset, or field name.
    """
    data = {"path": path, "type_path": type_path}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if offset != -2147483648:
        data["offset"] = offset
    if field_name:
        data["field_name"] = field_name
    if length > 0:
        data["length"] = length
    if comment:
        data["comment"] = comment
    return safe_post("set_struct_field_type", data)

@mcp.tool()
def delete_struct_field(path: str, ordinal: int = -1,
                        offset: int = -2147483648, field_name: str = "") -> str:
    """
    Delete a structure field by ordinal, offset, or field name.
    """
    data = {"path": path}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if offset != -2147483648:
        data["offset"] = offset
    if field_name:
        data["field_name"] = field_name
    return safe_post("delete_struct_field", data)

@mcp.tool()
def create_enum(name: str, category: str = "/", length: int = 4) -> str:
    """
    Create an enum data type.
    """
    return safe_post("create_enum", {"name": name, "category": category, "length": length})

@mcp.tool()
def set_enum_value(path: str, name: str, value: int, comment: str = "") -> str:
    """
    Add or replace an enum value.
    """
    return safe_post("set_enum_value", {
        "path": path, "name": name, "value": value, "comment": comment,
    })

@mcp.tool()
def create_typedef(name: str, target_path: str, category: str = "/") -> str:
    """
    Create a typedef to an existing data type.
    """
    return safe_post("create_typedef", {
        "name": name, "target_path": target_path, "category": category,
    })

@mcp.tool()
def create_pointer_type(target_path: str, name: str = "",
                        category: str = "/", size: int = -1) -> str:
    """
    Create or return a pointer type. If name is supplied, creates a typedef to the pointer.
    """
    data = {"target_path": target_path, "name": name, "category": category}
    if size > 0:
        data["size"] = size
    return safe_post("create_pointer_type", data)

@mcp.tool()
def create_array_type(element_type_path: str, count: int,
                      name: str = "", category: str = "/") -> str:
    """
    Create an array type. If name is supplied, creates a typedef to the array.
    """
    return safe_post("create_array_type", {
        "element_type_path": element_type_path, "count": count,
        "name": name, "category": category,
    })

@mcp.tool()
def create_function_definition_type(prototype: str) -> str:
    """
    Create a function-definition data type from a C-style function prototype.
    """
    return safe_post("create_function_definition_type", {"prototype": prototype})

@mcp.tool()
def set_function_name(function_address: str, name: str,
                      namespace: str = "", source: str = "user_defined") -> str:
    """
    Rename a function by address, optionally moving it into a namespace.
    """
    return safe_post("set_function_name", {
        "function_address": function_address, "name": name,
        "namespace": namespace, "source": source,
    })

@mcp.tool()
def set_function_return_type(function_address: str, type_path: str,
                             source: str = "user_defined") -> str:
    """
    Set a function return type by data type path/name.
    """
    return safe_post("set_function_return_type", {
        "function_address": function_address, "type_path": type_path, "source": source,
    })

@mcp.tool()
def set_function_calling_convention(function_address: str, calling_convention: str) -> str:
    """
    Set a function calling convention by name.
    """
    return safe_post("set_function_calling_convention", {
        "function_address": function_address, "calling_convention": calling_convention,
    })

@mcp.tool()
def set_function_no_return(function_address: str, enabled: str = "1") -> str:
    """
    Set or clear a function's no-return flag.
    """
    return safe_post("set_function_no_return", {"function_address": function_address, "enabled": enabled})

@mcp.tool()
def set_function_inline(function_address: str, enabled: str = "1") -> str:
    """
    Set or clear a function's inline flag.
    """
    return safe_post("set_function_inline", {"function_address": function_address, "enabled": enabled})

@mcp.tool()
def set_function_varargs(function_address: str, enabled: str = "1") -> str:
    """
    Set or clear a function's varargs flag.
    """
    return safe_post("set_function_varargs", {"function_address": function_address, "enabled": enabled})

@mcp.tool()
def set_function_thunk(function_address: str, target_address: str) -> str:
    """
    Set a function's thunk target.
    """
    return safe_post("set_function_thunk", {
        "function_address": function_address, "target_address": target_address,
    })

@mcp.tool()
def set_function_comment(function_address: str, text: str = "",
                         repeatable: str = "0", mode: str = "replace") -> str:
    """
    Set, append, prepend, or clear a function comment.
    """
    return safe_post("set_function_comment", {
        "function_address": function_address, "text": text,
        "repeatable": repeatable, "mode": mode,
    })

@mcp.tool()
def list_parameters(function_address: str = "", function_name: str = "") -> str:
    """
    List parameters for a function as structured JSON.
    """
    params = {}
    if function_address:
        params["function_address"] = function_address
    if function_name:
        params["function_name"] = function_name
    return "\n".join(safe_get("list_parameters", params))

@mcp.tool()
def rename_parameter(function_address: str, ordinal: int, new_name: str,
                     source: str = "user_defined") -> str:
    """
    Rename a parameter by ordinal.
    """
    return safe_post("rename_parameter", {
        "function_address": function_address, "ordinal": ordinal,
        "new_name": new_name, "source": source,
    })

@mcp.tool()
def set_parameter_type(function_address: str, ordinal: int, type_path: str,
                       source: str = "user_defined") -> str:
    """
    Set a parameter type by ordinal.
    """
    return safe_post("set_parameter_type", {
        "function_address": function_address, "ordinal": ordinal,
        "type_path": type_path, "source": source,
    })

@mcp.tool()
def set_parameter_storage(function_address: str, ordinal: int, storage: str,
                          source: str = "user_defined") -> str:
    """
    Set parameter storage using Ghidra's variable storage serialization.
    """
    return safe_post("set_parameter_storage", {
        "function_address": function_address, "ordinal": ordinal,
        "storage": storage, "source": source,
    })

@mcp.tool()
def add_parameter(function_address: str, name: str, type_path: str,
                  ordinal: int = -1, source: str = "user_defined") -> str:
    """
    Add or insert a function parameter.
    """
    return safe_post("add_parameter", {
        "function_address": function_address, "name": name,
        "type_path": type_path, "ordinal": ordinal, "source": source,
    })

@mcp.tool()
def remove_parameter(function_address: str, ordinal: int) -> str:
    """
    Remove a function parameter by ordinal.
    """
    return safe_post("remove_parameter", {"function_address": function_address, "ordinal": ordinal})

@mcp.tool()
def reorder_parameters(function_address: str, from_ordinal: int, to_ordinal: int) -> str:
    """
    Move a parameter from one ordinal to another.
    """
    return safe_post("reorder_parameters", {
        "function_address": function_address,
        "from_ordinal": from_ordinal,
        "to_ordinal": to_ordinal,
    })

@mcp.tool()
def rename_local_variable_by_storage(function_address: str, storage: str,
                                     new_name: str, source: str = "user_defined") -> str:
    """
    Rename a local/stack/parameter variable by exact storage string.
    """
    return safe_post("rename_local_variable_by_storage", {
        "function_address": function_address, "storage": storage,
        "new_name": new_name, "source": source,
    })

@mcp.tool()
def set_local_variable_type_by_storage(function_address: str, storage: str,
                                       type_path: str, source: str = "user_defined") -> str:
    """
    Retype a local/stack/parameter variable by exact storage string.
    """
    return safe_post("set_local_variable_type_by_storage", {
        "function_address": function_address, "storage": storage,
        "type_path": type_path, "source": source,
    })

@mcp.tool()
def create_stack_variable(function_address: str, stack_offset: int,
                          name: str, type_path: str,
                          source: str = "user_defined") -> str:
    """
    Create a stack variable in a function stack frame.
    """
    return safe_post("create_stack_variable", {
        "function_address": function_address, "stack_offset": stack_offset,
        "name": name, "type_path": type_path, "source": source,
    })

@mcp.tool()
def delete_stack_variable(function_address: str, stack_offset: int) -> str:
    """
    Delete/clear the stack variable at a stack offset.
    """
    return safe_post("delete_stack_variable", {
        "function_address": function_address, "stack_offset": stack_offset,
    })

@mcp.tool()
def set_stack_variable_type(function_address: str, stack_offset: int,
                            type_path: str, source: str = "user_defined") -> str:
    """
    Set the data type of the stack variable containing a stack offset.
    """
    return safe_post("set_stack_variable_type", {
        "function_address": function_address, "stack_offset": stack_offset,
        "type_path": type_path, "source": source,
    })


# ----- Added: write-capable / advanced tools -----------------------------

@mcp.tool()
def read_bytes(address: str, length: int = 16) -> str:
    """
    Read raw bytes from program memory and return them as lowercase hex (no spaces).
    Useful for inspecting data tables, structs, and patch records.

    Args:
        address: Start address in hex (e.g. "0x08000000" or "08000000").
        length:  Number of bytes to read (max 65536).
    """
    return "\n".join(safe_get("read_bytes", {"address": address, "length": length}))

@mcp.tool()
def write_bytes(address: str, hex: str) -> str:
    """
    Patch program memory at `address` with the bytes given as a hex string (whitespace ignored).
    Example: write_bytes("0x08000000", "deadbeef")
    """
    return safe_post("write_bytes", {"address": address, "hex": hex})

@mcp.tool()
def find_bytes(hex: str, start: str = "", limit: int = 20) -> list:
    """
    Search program memory for a byte pattern. Use '??' for wildcards.
    Example: find_bytes("fc7f0003", start="0x08000000")
    Returns the list of matching addresses (up to `limit`).
    """
    params = {"hex": hex, "limit": limit}
    if start:
        params["start"] = start
    return safe_get("find_bytes", params)

@mcp.tool()
def clear_listing(start: str, end: str) -> str:
    """
    Clear code units (instructions and data) in [start, end] inclusive.
    Useful for wiping bad auto-analysis from a region before re-disassembling.
    """
    return safe_post("clear_listing", {"start": start, "end": end})

@mcp.tool()
def disassemble(address: str) -> str:
    """
    Force-disassemble starting at `address` (follows fall-through and branches).
    Returns 'ok' or an error message. Call set_tmode first for ARM/Thumb.
    """
    return safe_post("disassemble", {"address": address})

@mcp.tool()
def set_tmode(address: str, value: str = "1") -> str:
    """
    Set the ARM TMode context register at `address`. value='1' = Thumb, '0' = ARM.
    Call BEFORE `disassemble` at that address when you know the mode.
    """
    return safe_post("set_tmode", {"address": address, "value": value})

@mcp.tool()
def set_tmode_range(start: str, end: str, value: str = "1") -> str:
    """
    Set the ARM TMode context register over an inclusive range.
    value='1' = Thumb, '0' = ARM.
    """
    return safe_post("set_tmode_range", {"start": start, "end": end, "value": value})

@mcp.tool()
def propagate_ldr_pc_refs(
    start: str = "",
    end: str = "",
    function_address: str = "",
    function_name: str = "",
    dry_run: bool = False,
    max_scan: int = 1000000,
    limit: int = 5000,
    seed_pointer_refs: bool = True,
) -> str:
    """
    Walk ARM/Thumb LDR-style instructions in the requested scope and add a READ
    memory reference for each [pc, #imm] literal target whose reference is
    missing from the Reference Manager.

    Works around the case where Ghidra's reference analyzers leave PC-relative
    constant-pool loads unreferenced even when all reference analyzers are
    enabled. Honors the current TMode at each instruction (ARM uses PC+8,
    Thumb uses (PC+4)&~3).

    When `seed_pointer_refs=True` (default), if the constant-pool slot holds a
    value that resolves to loaded memory (e.g. EWRAM/IWRAM pointer like
    gSaveBlock2Ptr=0x03005390), also adds a DATA reference from the LDR
    instruction AND from the constant-pool slot to that pointer's target. This
    makes `xrefs_to(<pointer_target>)` enumerate every function that loads the
    pointer in a single query. Pointer seeding runs for already-present LDR
    refs too, so re-running on a previously-propagated program backfills the
    pointer-target edges.

    Scope: function (by address or name), or [start, end] range, or full program.
    """
    payload = {
        "dry_run": "true" if dry_run else "false",
        "max_scan": str(max_scan),
        "limit": str(limit),
        "seed_pointer_refs": "true" if seed_pointer_refs else "false",
    }
    if start: payload["start"] = start
    if end: payload["end"] = end
    if function_address: payload["function_address"] = function_address
    if function_name: payload["function_name"] = function_name
    return safe_post("propagate_ldr_pc_refs", payload)

@mcp.tool()
def create_thumb_function_from_pointer(
    pointer_address: str,
    name: str = "",
    force_mode: str = "",
    create_pointer_data: bool = True,
    add_reference: bool = True,
) -> str:
    """
    Read the 4-byte function pointer stored at `pointer_address`, mask the
    Thumb bit (low bit of the value), set the ARM TMode context register
    accordingly at the target, clear any wrong-mode disassembly already at the
    target, then disassemble and create a function there.

    Works around Ghidra defaulting to ARM disassembly for functions created
    from constant-pool function pointers.

    `force_mode` overrides the auto-detected mode: 'thumb' or 'arm'.
    """
    payload = {
        "pointer_address": pointer_address,
        "create_pointer_data": "true" if create_pointer_data else "false",
        "add_reference": "true" if add_reference else "false",
    }
    if name: payload["name"] = name
    if force_mode: payload["force_mode"] = force_mode
    return safe_post("create_thumb_function_from_pointer", payload)

@mcp.tool()
def scan_thumb_pointer_table(
    start: str,
    end: str = "",
    max_entries: int = 256,
    require_executable: bool = True,
    stop_on_invalid: bool = True,
    create_functions: bool = True,
) -> str:
    """
    Walk `[start, end]` (or `max_entries` words from `start`) as a table of
    function pointers, masking each Thumb bit and creating a function at each
    resolved target. Stops on the first invalid entry by default (zero,
    out-of-memory, or — when `require_executable=true` — pointing into a
    non-executable block).
    """
    payload = {
        "start": start,
        "max_entries": str(max_entries),
        "require_executable": "true" if require_executable else "false",
        "stop_on_invalid": "true" if stop_on_invalid else "false",
        "create_functions": "true" if create_functions else "false",
    }
    if end: payload["end"] = end
    return safe_post("scan_thumb_pointer_table", payload)

@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """
    Create (or rename, if it already exists) a function at `address`.
    """
    return safe_post("create_function", {"address": address, "name": name})

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete the function at or containing `address`.
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a user-defined label/symbol at `address`.
    """
    return safe_post("create_label", {"address": address, "name": name})

@mcp.tool()
def create_data(address: str, type: str, count: int = 1) -> str:
    """
    Apply a simple data type at `address`. type ∈ {byte, word, dword, qword, string}.
    If count > 1, applies an array of that type.
    """
    return safe_post("create_data", {"address": address, "type": type, "count": count})

@mcp.tool()
def analyze() -> str:
    """
    Re-run full auto-analysis on the current program. Returns the new function count.
    """
    return safe_post("analyze", {})

@mcp.tool()
def set_image_base(address: str) -> str:
    """
    Move the program's image base to `address` (useful when raw binary loaded at 0
    should actually live at a memory-mapped location like 0x08000000 for GBA ROMs).
    """
    return safe_post("set_image_base", {"address": address})

@mcp.tool()
def create_initialized_block(name: str, address: str, hex: str,
                             read: str = "1", write: str = "0", execute: str = "1") -> str:
    """
    Create an initialized memory block from a hex byte string.
    Useful for adding a rebased block such as EWRAM at 0x02000000.
    """
    return safe_post("create_initialized_block", {
        "name": name,
        "address": address,
        "hex": hex,
        "read": read,
        "write": write,
        "execute": execute,
    })

@mcp.tool()
def create_uninitialized_block(name: str, address: str, size: int,
                               read: str = "1", write: str = "1", execute: str = "0") -> str:
    """
    Create an uninitialized memory block with configurable permissions.
    """
    return safe_post("create_uninitialized_block", {
        "name": name,
        "address": address,
        "size": str(size),
        "read": read,
        "write": write,
        "execute": execute,
    })

@mcp.tool()
def remove_memory_block(name: str = "", address: str = "") -> str:
    """
    Remove a memory block by name or by any address contained inside it.
    """
    return safe_post("remove_memory_block", {"name": name, "address": address})

@mcp.tool()
def set_block_permissions(name: str = "", address: str = "",
                          read: str = "", write: str = "", execute: str = "") -> str:
    """
    Set memory block permissions by name or contained address.
    Pass only the permission fields that should change.
    """
    return safe_post("set_block_permissions", {
        "name": name,
        "address": address,
        "read": read,
        "write": write,
        "execute": execute,
    })

@mcp.tool()
def create_function_range(entry: str, start: str = "", end: str = "",
                          ranges: str = "", name: str = "",
                          source: str = "user_defined") -> str:
    """
    Create or update a function at `entry` with an explicit body range.
    Provide either start+end for a single range, or `ranges` as
    comma-separated `start-end` pairs (e.g. "0x1000-0x1010,0x1020-0x1030").
    The entry address must be inside the supplied range.
    """
    data = {"entry": entry, "name": name, "source": source}
    if start: data["start"] = start
    if end: data["end"] = end
    if ranges: data["ranges"] = ranges
    return safe_post("create_function_range", data)

@mcp.tool()
def set_function_body(function_address: str = "", function_name: str = "",
                      start: str = "", end: str = "", ranges: str = "") -> str:
    """
    Replace the body of a function with the supplied range(s).
    The function's entry point must lie inside the new body.
    """
    data = {"function_address": function_address, "function_name": function_name}
    if start: data["start"] = start
    if end: data["end"] = end
    if ranges: data["ranges"] = ranges
    return safe_post("set_function_body", data)

@mcp.tool()
def add_function_body_range(function_address: str = "", function_name: str = "",
                            start: str = "", end: str = "", ranges: str = "") -> str:
    """
    Extend an existing function's body with additional range(s).
    """
    data = {"function_address": function_address, "function_name": function_name}
    if start: data["start"] = start
    if end: data["end"] = end
    if ranges: data["ranges"] = ranges
    return safe_post("add_function_body_range", data)

@mcp.tool()
def remove_function_body_range(function_address: str = "", function_name: str = "",
                               start: str = "", end: str = "", ranges: str = "") -> str:
    """
    Remove range(s) from an existing function's body. The entry point cannot be removed.
    """
    data = {"function_address": function_address, "function_name": function_name}
    if start: data["start"] = start
    if end: data["end"] = end
    if ranges: data["ranges"] = ranges
    return safe_post("remove_function_body_range", data)

@mcp.tool()
def repair_function_body(function_address: str = "", function_name: str = "") -> str:
    """
    Recompute and fix up a function's body by following flow from its entry point.
    Useful for switch-heavy code or hand-tuned assembly where the body got stale.
    """
    return safe_post("repair_function_body", {
        "function_address": function_address,
        "function_name": function_name,
    })

@mcp.tool()
def create_union(name: str, category: str = "/") -> str:
    """
    Create a new union data type.
    """
    return safe_post("create_union", {"name": name, "category": category})

@mcp.tool()
def delete_union(path: str) -> str:
    """
    Delete a union data type by path/name.
    """
    return safe_post("delete_union", {"path": path})

@mcp.tool()
def add_union_field(path: str, type_path: str, field_name: str = "",
                    length: int = -1, comment: str = "") -> str:
    """
    Add a field to a union.
    """
    data = {"path": path, "type_path": type_path, "field_name": field_name, "comment": comment}
    if length > 0:
        data["length"] = length
    return safe_post("add_union_field", data)

@mcp.tool()
def rename_union_field(path: str, new_name: str,
                       ordinal: int = -1, field_name: str = "") -> str:
    """
    Rename a union field by ordinal or current field name.
    """
    data = {"path": path, "new_name": new_name}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if field_name:
        data["field_name"] = field_name
    return safe_post("rename_union_field", data)

@mcp.tool()
def set_union_field_type(path: str, type_path: str,
                         ordinal: int = -1, field_name: str = "",
                         length: int = -1, comment: str = "") -> str:
    """
    Replace a union field's data type by ordinal or field name.
    """
    data = {"path": path, "type_path": type_path}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if field_name:
        data["field_name"] = field_name
    if length > 0:
        data["length"] = length
    if comment:
        data["comment"] = comment
    return safe_post("set_union_field_type", data)

@mcp.tool()
def delete_union_field(path: str, ordinal: int = -1, field_name: str = "") -> str:
    """
    Delete a union field by ordinal or field name.
    """
    data = {"path": path}
    if ordinal >= 0:
        data["ordinal"] = ordinal
    if field_name:
        data["field_name"] = field_name
    return safe_post("delete_union_field", data)

@mcp.tool()
def clear_data(address: str, length: int = 0, clear_context: str = "0") -> str:
    """
    Clear defined code/data starting at `address`. If `length` is 0,
    clears the single defined data item that starts at or contains `address`.
    Set clear_context='1' to also clear context register values.
    """
    return safe_post("clear_data", {
        "address": address, "length": str(length), "clear_context": clear_context,
    })

@mcp.tool()
def create_string(address: str, encoding: str = "ascii",
                  length: int = -1, null_terminated: str = "1") -> str:
    """
    Apply a string data type at `address`.
    encoding ∈ {ascii, utf8, utf16}. If `null_terminated` is "1" (default),
    creates a terminated string of variable length; otherwise `length` bytes
    must be supplied.
    """
    data = {"address": address, "encoding": encoding, "null_terminated": null_terminated}
    if length > 0:
        data["length"] = length
    return safe_post("create_string", data)

@mcp.tool()
def create_array(address: str, element_type_path: str, count: int) -> str:
    """
    Apply an array of an existing data type at `address`. Clears any existing
    code/data covered by the array before applying.
    """
    return safe_post("create_array", {
        "address": address, "element_type_path": element_type_path, "count": count,
    })

@mcp.tool()
def list_analyzers(applicable: str = "1", offset: int = 0, limit: int = 0) -> list:
    """
    List analyzers registered with Ghidra. By default only those whose
    `canAnalyze()` returns true for the current program (applicable="0" to list all).
    Each entry includes name, type, priority, default_enabled, can_analyze,
    supports_one_time, and the current `enabled` value on this program.
    """
    params = {"applicable": applicable, "offset": offset}
    if limit > 0:
        params["limit"] = limit
    return safe_get("list_analyzers", params)

@mcp.tool()
def get_analyzer_options(name: str) -> list:
    """
    Return enable state and all per-analyzer options (name, type, value,
    default, description) for the analyzer with the given name.
    """
    return safe_get("get_analyzer_options", {"name": name})

@mcp.tool()
def set_analyzer_option(name: str, option: str = "", value: str = "") -> str:
    """
    Set an analyzer option. If `option` is empty, sets the analyzer's enable
    flag itself (`value` should be "true"/"false"). Otherwise `option` names
    the leaf option below the analyzer and `value` is its string representation
    (booleans, integers, enums are converted by Ghidra's OptionType).
    """
    return safe_post("set_analyzer_option", {
        "name": name, "option": option, "value": value,
    })

@mcp.tool()
def enable_analyzer(name: str) -> str:
    """Enable the named analyzer for the current program."""
    return safe_post("enable_analyzer", {"name": name})

@mcp.tool()
def disable_analyzer(name: str) -> str:
    """Disable the named analyzer for the current program."""
    return safe_post("disable_analyzer", {"name": name})

@mcp.tool()
def run_analyzer(name: str, start: str = "", end: str = "",
                 function_address: str = "", function_name: str = "") -> str:
    """
    Schedule a single analyzer to run over the supplied range and start
    analysis. If no range is supplied, runs across the full program memory.
    A function range can be specified via function_address or function_name.
    The analyzer must support one-time analysis.
    """
    return safe_post("run_analyzer", {
        "name": name, "start": start, "end": end,
        "function_address": function_address, "function_name": function_name,
    })

@mcp.tool()
def analyze_range(start: str = "", end: str = "",
                  function_address: str = "", function_name: str = "") -> str:
    """
    Re-analyze the supplied address range. If start/end are empty and no
    function is given, re-analyzes the full program memory.
    """
    return safe_post("analyze_range", {
        "start": start, "end": end,
        "function_address": function_address, "function_name": function_name,
    })

@mcp.tool()
def analyze_function(function_address: str = "", function_name: str = "",
                     address: str = "") -> str:
    """
    Re-analyze the body of a single function identified by address or name.
    """
    return safe_post("analyze_function", {
        "function_address": function_address,
        "function_name": function_name,
        "address": address,
    })

@mcp.tool()
def get_analysis_status() -> str:
    """
    Return whether analysis is running, total accumulated analysis time (ms),
    the message log text, and per-task timings recorded by the analyzer.
    """
    return "\n".join(safe_get("get_analysis_status"))

@mcp.tool()
def get_analysis_log() -> str:
    """
    Return the AutoAnalysisManager message log (errors, warnings, info)
    and the cumulative task time summary.
    """
    return "\n".join(safe_get("get_analysis_log"))

@mcp.tool()
def list_undefined_ranges(start: str = "", end: str = "",
                          min_length: int = 1,
                          offset: int = 0, limit: int = 1000) -> list:
    """
    List address ranges with no defined code or data (initialized memory).
    Optionally scoped by start/end and filtered by min_length.
    """
    return safe_get("list_undefined_ranges", {
        "start": start, "end": end,
        "min_length": min_length, "offset": offset, "limit": limit,
    })

@mcp.tool()
def list_executable_undefined_ranges(start: str = "", end: str = "",
                                     min_length: int = 1,
                                     offset: int = 0, limit: int = 1000) -> list:
    """
    Same as list_undefined_ranges but restricted to executable memory blocks.
    Useful for spotting unanalyzed code regions in firmware.
    """
    return safe_get("list_executable_undefined_ranges", {
        "start": start, "end": end,
        "min_length": min_length, "offset": offset, "limit": limit,
    })

@mcp.tool()
def find_possible_functions(start: str = "", end: str = "",
                            alignment: int = 0, max_scan: int = 50000,
                            offset: int = 0, limit: int = 100) -> list:
    """
    Scan undefined executable ranges for byte sequences that look like
    valid function starts (uses Ghidra's PseudoDisassembler.isValidSubroutine).
    `alignment` defaults to the architecture's instruction alignment.
    `max_scan` caps the number of candidate starts inspected.
    """
    return safe_get("find_possible_functions", {
        "start": start, "end": end,
        "alignment": alignment, "max_scan": max_scan,
        "offset": offset, "limit": limit,
    })

@mcp.tool()
def program_info() -> str:
    """
    Show language, compiler spec, image base, min/max address, and function count.
    """
    return "\n".join(safe_get("program_info"))

@mcp.tool()
def get_program_info() -> str:
    """
    Alias of program_info(). Same output.
    """
    return "\n".join(safe_get("get_program_info"))

@mcp.tool()
def list_endpoints() -> list:
    """
    List every HTTP endpoint exposed by the Ghidra MCP plugin. Useful for
    discovering available functionality without leaving the agent loop.
    """
    return safe_get("list_endpoints")

@mcp.tool()
def count_functions() -> str:
    """
    Return the total number of functions in the current program as JSON.
    """
    return safe_get("count_functions")[0] if safe_get("count_functions") else ""

@mcp.tool()
def list_memory_blocks(offset: int = 0, limit: int = 100) -> list:
    """
    List memory blocks with start/end/size and r/w/x/initialized/overlay flags.
    """
    return safe_get("list_memory_blocks", {"offset": offset, "limit": limit})

@mcp.tool()
def seed_functions_in_range(start: str, end: str, mode: str = "thumb",
                            detect_thumb_no_lr: bool = False,
                            max_seeds: int = 20000,
                            dry_run: bool = False,
                            preview_limit: int = 100) -> str:
    """
    Walk an executable address range and create a function at every position
    that looks like an ARM/Thumb function prologue (`push {…}`).

    Pattern matches in undefined initialized executable memory:
      - Thumb `push {…, lr}` (0xB5xx)        — 2-byte aligned
      - Thumb `push {…}`     (0xB4xx)        — 2-byte aligned, opt-in (detect_thumb_no_lr)
      - ARM `stmdb sp!, {…}` (0xE92Dxxxx)    — 4-byte aligned

    Parameters
    ----------
    start, end      : address range (inclusive)
    mode            : "thumb", "arm", or "both" (default "thumb")
    detect_thumb_no_lr : also seed on Thumb push without LR (noisy, default False)
    max_seeds       : cap on functions created (default 20000)
    dry_run         : if True, only report candidate counts and a small sample
    preview_limit   : cap on size of created/failed previews in the response

    Returns JSON envelope with scanned_bytes, *_candidates, created_count,
    failed_count, and small previews of created/failed addresses.

    Built to speed up bring-up of dense ARM/Thumb ROMs (e.g. GBA) where Ghidra's
    auto-analysis stops at ~1.6k functions on a fresh import.
    """
    return safe_post("seed_functions_in_range", {
        "start": start, "end": end, "mode": mode,
        "detect_thumb_no_lr": "true" if detect_thumb_no_lr else "false",
        "max_seeds": str(max_seeds),
        "dry_run": "true" if dry_run else "false",
        "preview_limit": str(preview_limit),
    })

@mcp.tool()
def string_table_at(base: str, stride: int, count: int,
                    encoding: str = "ascii",
                    trim_null: bool = True,
                    apply: bool = False,
                    preview_limit: int = 1024) -> list:
    """
    Extract a flat fixed-stride C-string table from memory. Useful for ROMs
    and other binaries that store names (species, moves, items, …) as a
    tightly-packed array of fixed-width null-padded strings — much more
    precise than byte-level search when the stride is already known.

    Parameters
    ----------
    base          : start address of the table (required)
    stride        : bytes per entry (> 0, required)
    count         : number of entries to read (> 0, required)
    encoding      : "ascii" (default), "utf8", "latin1", or "raw" (hex bytes)
    trim_null     : trim each entry at the first 0x00 byte (default True)
    apply         : if True, also create string data in Ghidra at every entry
                    (single transaction). Default False (read-only).
    preview_limit : cap on entries embedded in the response (default 1024)

    Returns JSON envelope with base, stride, count, encoding, entries
    (index, address, text or raw_hex, length), readable_entries, and (when
    apply=True) applied_count plus any apply_errors.
    """
    return safe_get("string_table_at", {
        "base": base,
        "stride": str(stride),
        "count": str(count),
        "encoding": encoding,
        "trim_null": "true" if trim_null else "false",
        "apply": "true" if apply else "false",
        "preview_limit": str(preview_limit),
    })

# ---------------------------------------------------------------------------
# Phase 9: Discovery helpers (pointer/jump tables, raw string scans)
# ---------------------------------------------------------------------------

@mcp.tool()
def find_pointer_tables(start: str = "", end: str = "",
                        min_entries: int = 4, alignment: int = 0,
                        executable_targets: bool = False,
                        max_scan: int = 200000,
                        offset: int = 0, limit: int = 100) -> list:
    """
    Scan undefined initialized memory for runs of pointer-sized values that
    reference loaded memory. Returns table candidates with their entries.
    Set executable_targets=true to require targets in executable blocks.
    """
    return safe_get("find_pointer_tables", {
        "start": start, "end": end,
        "min_entries": min_entries, "alignment": alignment,
        "executable_targets": "true" if executable_targets else "false",
        "max_scan": max_scan, "offset": offset, "limit": limit,
    })

@mcp.tool()
def find_jump_tables(function_address: str = "", function_name: str = "",
                     start: str = "", end: str = "", min_entries: int = 3,
                     offset: int = 0, limit: int = 100) -> list:
    """
    Identify computed jump instructions whose recorded references resemble a
    jump table (>= min_entries flow destinations). Scope can be a function
    or address range; default is the whole program.
    """
    return safe_get("find_jump_tables", {
        "function_address": function_address, "function_name": function_name,
        "start": start, "end": end,
        "min_entries": min_entries, "offset": offset, "limit": limit,
    })

@mcp.tool()
def find_ascii_strings(start: str = "", end: str = "",
                       min_length: int = 4, undefined_only: bool = True,
                       max_scan: int = 5_000_000,
                       offset: int = 0, limit: int = 500) -> list:
    """
    Scan memory for runs of printable ASCII characters. By default only
    undefined ranges are scanned so existing strings are not re-reported.
    """
    return safe_get("find_ascii_strings", {
        "start": start, "end": end,
        "min_length": min_length,
        "undefined_only": "true" if undefined_only else "false",
        "max_scan": max_scan, "offset": offset, "limit": limit,
    })

@mcp.tool()
def find_utf16_strings(start: str = "", end: str = "",
                       min_length: int = 6, undefined_only: bool = True,
                       max_scan: int = 5_000_000,
                       offset: int = 0, limit: int = 500) -> list:
    """
    Scan memory for runs of UTF-16 characters (printable ASCII subset).
    Returns the start address, character count, encoding, and preview text.
    """
    return safe_get("find_utf16_strings", {
        "start": start, "end": end,
        "min_length": min_length,
        "undefined_only": "true" if undefined_only else "false",
        "max_scan": max_scan, "offset": offset, "limit": limit,
    })

# ---------------------------------------------------------------------------
# Phase 10: Program lifecycle
# ---------------------------------------------------------------------------

@mcp.tool()
def list_open_programs() -> str:
    """
    List all programs currently open in the Ghidra ProgramManager.
    Each entry includes name, path, language, image base, function count,
    changed/read-only flags, and whether it is the current program.
    """
    return "\n".join(safe_get("list_open_programs"))

@mcp.tool()
def select_program(name: str = "", path: str = "") -> str:
    """
    Make the named or path-identified open program the current program.
    """
    return safe_post("select_program", {"name": name, "path": path})

@mcp.tool()
def save_program(name: str = "", path: str = "") -> str:
    """
    Save the named/path-identified program (or the current program if both
    are empty) to its existing DomainFile in the project.
    """
    return safe_post("save_program", {"name": name, "path": path})

@mcp.tool()
def close_program(name: str = "", path: str = "",
                  ignore_changes: bool = False) -> str:
    """
    Close the named/path-identified program (or current program). Pass
    ignore_changes=true to discard unsaved modifications.
    """
    return safe_post("close_program", {
        "name": name, "path": path,
        "ignore_changes": "true" if ignore_changes else "false",
    })

@mcp.tool()
def import_file(path: str, folder: str = "", open: bool = True,
                loader_name: str = "", language_id: str = "",
                compiler_spec: str = "", image_base: str = "",
                loader_options: str = "") -> str:
    """
    Import a binary from disk into the active Ghidra project. By default
    auto-detects the loader; pass loader_name (e.g. "GameBoyAdvanceLoader",
    "BinaryLoader") to force a specific loader, and language_id/compiler_spec
    (e.g. "ARM:LE:32:v4t" / "default") for raw-binary loads. image_base sets
    the program's image base after import. loader_options accepts either
    "key1=value1,key2=value2" or a JSON object string of loader options.
    """
    return safe_post("import_file", {
        "path": path, "folder": folder,
        "open": "1" if open else "0",
        "loader_name": loader_name,
        "language_id": language_id,
        "compiler_spec": compiler_spec,
        "image_base": image_base,
        "loader_options": loader_options,
    })

@mcp.tool()
def open_program(path: str) -> str:
    """
    Open a program by its project path (e.g., /MyBinary) in the current tool.
    """
    return safe_post("open_program", {"path": path})

# ---------------------------------------------------------------------------
# Phase 11: Exports
# ---------------------------------------------------------------------------

@mcp.tool()
def export_bytes(start: str, end: str = "", length: int = 0,
                 path: str = "") -> str:
    """
    Read a byte range from program memory. With `path`, writes raw bytes to
    a file and returns the absolute path. Without `path`, returns hex inline.
    Specify either `end` (inclusive) or `length`.
    """
    return safe_post("export_bytes", {
        "start": start, "end": end,
        "length": str(length) if length else "",
        "path": path,
    })

@mcp.tool()
def export_patched_binary(path: str, initialized_only: bool = True) -> str:
    """
    Concatenate program memory blocks to a file on disk. By default only
    initialized blocks are written.
    """
    return safe_post("export_patched_binary", {
        "path": path,
        "initialized_only": "true" if initialized_only else "false",
    })

@mcp.tool()
def export_symbols(format: str = "json", path: str = "",
                   user_only: bool = False) -> str:
    """
    Export all symbols. format=json|csv|text. If `path` is given, writes to
    disk; otherwise returns the body. user_only=true keeps only user-defined.
    """
    return safe_post("export_symbols", {
        "format": format, "path": path,
        "user_only": "true" if user_only else "false",
    })

@mcp.tool()
def export_function_map(format: str = "json", path: str = "") -> str:
    """
    Export entries, names, body sizes and signatures for every function.
    format=json|csv|text. Set `path` to write to disk.
    """
    return safe_post("export_function_map", {"format": format, "path": path})

@mcp.tool()
def export_c_header(path: str = "", category: str = "") -> str:
    """
    Export struct, union, enum, and typedef data types as a C-like header.
    `category` substring filters by category path. Returns body or writes
    to `path` if provided.
    """
    return safe_post("export_c_header", {"path": path, "category": category})

@mcp.tool()
def export_analysis_report(format: str = "json", path: str = "") -> str:
    """
    Produce a summary of the program: counts of functions, user-defined
    symbols, comments, types, patches, undefined executable bytes, etc.
    """
    return safe_post("export_analysis_report", {"format": format, "path": path})

# ---------------------------------------------------------------------------
# Phase 12: Patch helpers
# ---------------------------------------------------------------------------

@mcp.tool()
def assemble_instruction(address: str, instruction: str) -> str:
    """
    Assemble a single instruction without writing it to memory. Returns the
    encoded bytes so the caller can review them before patching.
    """
    return safe_post("assemble_instruction", {
        "address": address, "instruction": instruction,
    })

@mcp.tool()
def patch_instruction(address: str, instruction: str, rationale: str = "",
                      dry_run: bool = False) -> str:
    """
    Assemble and write a single instruction at `address`. Records a patch
    history entry containing the original and new bytes.
    """
    return safe_post("patch_instruction", {
        "address": address, "instruction": instruction,
        "rationale": rationale,
        "dry_run": "true" if dry_run else "false",
    })

@mcp.tool()
def nop_range(start: str, end: str = "", length: int = 0,
              rationale: str = "", dry_run: bool = False) -> str:
    """
    Overwrite a range of bytes with the architecture's NOP encoding.
    Specify either `end` or `length`. Records the original bytes.
    """
    return safe_post("nop_range", {
        "start": start, "end": end,
        "length": str(length) if length else "",
        "rationale": rationale,
        "dry_run": "true" if dry_run else "false",
    })

@mcp.tool()
def patch_call_target(address: str, target: str, rationale: str = "",
                      dry_run: bool = False) -> str:
    """
    Re-assemble the call at `address` so that it targets `target`. Fails if
    the re-assembled instruction would not fit in the original slot.
    """
    return safe_post("patch_call_target", {
        "address": address, "target": target,
        "rationale": rationale,
        "dry_run": "true" if dry_run else "false",
    })

@mcp.tool()
def patch_branch_target(address: str, target: str, rationale: str = "",
                        dry_run: bool = False) -> str:
    """
    Re-assemble the jump/branch at `address` so that it targets `target`.
    """
    return safe_post("patch_branch_target", {
        "address": address, "target": target,
        "rationale": rationale,
        "dry_run": "true" if dry_run else "false",
    })

@mcp.tool()
def create_patch_record(address: str, new_bytes: str,
                        original_bytes: str = "",
                        rationale: str = "") -> str:
    """
    Manually create a patch record for byte changes already applied (or to
    be applied) at `address`. `new_bytes`/`original_bytes` are hex strings.
    If `original_bytes` is empty, the current memory bytes are captured.
    """
    return safe_post("create_patch_record", {
        "address": address, "new_bytes": new_bytes,
        "original_bytes": original_bytes, "rationale": rationale,
    })

@mcp.tool()
def list_patches(active_only: bool = False,
                 offset: int = 0, limit: int = 100) -> list:
    """
    List patch history records (id, address, original/new bytes, rationale,
    timestamp, reverted flag). Set active_only=true to omit reverted ones.
    """
    return safe_get("list_patches", {
        "active_only": "true" if active_only else "false",
        "offset": offset, "limit": limit,
    })

@mcp.tool()
def revert_patch(id: int) -> str:
    """
    Restore the original bytes recorded for a patch and mark it reverted.
    """
    return safe_post("revert_patch", {"id": str(id)})

# ---------------------------------------------------------------------------
# Phase 13: Project lifecycle, async analysis, navigation, bring-up
# ---------------------------------------------------------------------------

@mcp.tool()
def project_info() -> str:
    """
    Return information about the active Ghidra project: name, locator, file
    count, the active tool, and current program (if any).
    """
    return "\n".join(safe_get("project_info"))

@mcp.tool()
def open_project(path: str) -> str:
    """
    Open a Ghidra project by its on-disk path (path to either the .gpr file
    or the project directory). Closes the currently active project first.
    """
    return safe_post("open_project", {"path": path})

@mcp.tool()
def close_project(save: bool = True) -> str:
    """
    Close the active Ghidra project. By default saves project state first.
    """
    return safe_post("close_project", {"save": "true" if save else "false"})

@mcp.tool()
def create_project(path: str, name: str = "") -> str:
    """
    Create a new Ghidra project at the given directory path. `name` defaults
    to the directory's basename. Makes the new project active.
    """
    return safe_post("create_project", {"path": path, "name": name})

@mcp.tool()
def save_project() -> str:
    """
    Save the active Ghidra project state (recent files, folders index).
    """
    return safe_post("save_project", {})

@mcp.tool()
def list_project_files(folder: str = "/", recursive: bool = True) -> str:
    """
    Enumerate DomainFiles under `folder` in the active project. By default
    recurses into subfolders. Each entry returns name, path, content type,
    object class, and read-only/versioned flags.
    """
    return "\n".join(safe_get("list_project_files", {
        "folder": folder,
        "recursive": "1" if recursive else "0",
    }))

@mcp.tool()
def project_file_exists(path: str) -> str:
    """
    Check whether a project path exists in the active project. Returns the
    file's content type and domain object class if it does.
    """
    return "\n".join(safe_get("project_file_exists", {"path": path}))

@mcp.tool()
def delete_project_file(path: str) -> str:
    """
    Delete a DomainFile from the active project by its project path.
    """
    return safe_post("delete_project_file", {"path": path})

@mcp.tool()
def list_loaders() -> str:
    """
    Enumerate all installed Ghidra loaders (importer classes). Each entry has
    `name` (display name from Loader.getName()), `loader_name` (simple class
    name — the value to pass as import_file/bring_up `loader_name`), and
    `class` (fully-qualified class name).
    """
    return "\n".join(safe_get("list_loaders"))

@mcp.tool()
def list_languages(processor: str = "", language_id: str = "") -> str:
    """
    Enumerate installed Ghidra languages. Optionally filter by processor
    (e.g. "ARM") or exact language_id.
    """
    return "\n".join(safe_get("list_languages", {
        "processor": processor,
        "language_id": language_id,
    }))

@mcp.tool()
def list_compiler_specs(language_id: str) -> str:
    """
    Enumerate compiler specs compatible with the given language_id.
    """
    return "\n".join(safe_get("list_compiler_specs", {"language_id": language_id}))

@mcp.tool()
def start_analysis(reanalyze: bool = False) -> str:
    """
    Kick off auto-analysis on the current program in a background thread and
    return a job_id immediately. Poll with analysis_progress(job_id).
    Pass reanalyze=true to call reAnalyzeAll(null) first (forces a full
    re-run of all applicable analyzers).
    """
    return safe_post("start_analysis", {
        "reanalyze": "true" if reanalyze else "false",
    })

@mcp.tool()
def analysis_progress(job_id: str = "") -> str:
    """
    Poll the progress of an async analysis job. Without a job_id, lists all
    known jobs. Each record carries state, percent, current task,
    elapsed_ms, and function counts before/after.
    """
    return "\n".join(safe_get("analysis_progress",
                              {"job_id": job_id} if job_id else None))

@mcp.tool()
def cancel_analysis(job_id: str) -> str:
    """
    Cancel a running async analysis job. The TaskMonitor is set cancelled
    and queued analyzer tasks are dropped.
    """
    return safe_post("cancel_analysis", {"job_id": job_id})

@mcp.tool()
def ready() -> str:
    """
    Single-shot readiness summary: project state, tool kind, current
    program, open programs, active analysis jobs, and `agent_hints` —
    short reminders of capabilities the agent should not need to ask
    the user about (e.g. importing binaries, enabling the disabled-by-
    default `Scalar Operand References` analyzer).
    """
    return "\n".join(safe_get("ready"))

@mcp.tool()
def agent_hints() -> str:
    """
    Return only the agent capability hints from `/ready`. Useful as a
    lightweight "what can I do here?" probe.

    Always-on tips include: you can import binaries yourself
    (`import_file`, `open_program`, `bring_up`), and you should enable
    the `Scalar Operand References` analyzer (disabled by default —
    `enable_analyzer(name="Scalar Operand References")` then
    `analyze()`) to surface tens of thousands of additional references
    on dense binaries.
    """
    return "\n".join(safe_get("agent_hints"))

@mcp.tool()
def goto(address: str) -> str:
    """
    Move Ghidra's listing/decompiler cursor to `address`.
    """
    return safe_post("goto", {"address": address})

@mcp.tool()
def select_range(start: str, end: str) -> str:
    """
    Select the address range [start, end] in Ghidra's listing and goto start.
    """
    return safe_post("select_range", {"start": start, "end": end})

@mcp.tool()
def ensure_gba_memory_map(overwrite: bool = False) -> str:
    """
    Create the canonical GBA memory map (BIOS/EWRAM/IWRAM/IO/Palette/VRAM/
    OAM/ROM mirror/SRAM) as uninitialized blocks with correct permissions.
    By default skips regions that already have a block at the start
    address; pass overwrite=true to drop and recreate them.
    """
    return safe_post("ensure_gba_memory_map", {
        "overwrite": "true" if overwrite else "false",
    })

@mcp.tool()
def bring_up(rom_path: str, project_path: str = "",
             loader_name: str = "", language_id: str = "",
             compiler_spec: str = "", image_base: str = "",
             loader_options: str = "", folder: str = "",
             ensure_gba: bool = False, analyze: bool = True,
             wait_ms: int = 0, seed_addresses: str = "",
             seed_image_base: bool = False) -> str:
    """
    One-shot bring-up of a binary: open the project (if project_path is
    given), import the ROM if not already imported (or open the existing
    program), optionally ensure the GBA memory map, optionally seed
    disassembly at given addresses, and start analysis asynchronously.

    Raw-binary loaders don't produce entry points on their own, so the first
    analysis pass will find 0 functions. Pass `seed_addresses` (a comma-
    separated list of addresses, e.g. reset/interrupt vectors) and/or
    `seed_image_base=true` to disassemble at those locations BEFORE analysis
    runs, giving the analyzer something to follow. With wait_ms>0, blocks up
    to that many milliseconds waiting for analysis to complete.
    """
    return safe_post("bring_up", {
        "rom_path": rom_path,
        "project_path": project_path,
        "loader_name": loader_name,
        "language_id": language_id,
        "compiler_spec": compiler_spec,
        "image_base": image_base,
        "loader_options": loader_options,
        "folder": folder,
        "ensure_gba": "true" if ensure_gba else "false",
        "analyze": "true" if analyze else "false",
        "wait_ms": str(wait_ms),
        "seed_addresses": seed_addresses,
        "seed_image_base": "true" if seed_image_base else "false",
    })


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
