# /// script
# dependencies = [
#   "requests<3",
#   "mcp<2",
# ]
# ///

from mcp.server.fastmcp import FastMCP
import requests

ida_server_url = "http://localhost:8080"

mcp = FastMCP("ida-mcp")

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request. If 'params' is given, we convert it to a query string.
    """
    if params is None:
        params = {}
    qs = [f"{k}={v}" for k, v in params.items()]
    query_string = "&".join(qs)
    url = f"{ida_server_url}/{endpoint}"
    if query_string:
        url += "?" + query_string

    try:
        response = requests.get(url, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        if isinstance(data, dict):
            response = requests.post(f"{ida_server_url}/{endpoint}", data=data, timeout=5)
        else:
            response = requests.post(f"{ida_server_url}/{endpoint}", data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}" 

@mcp.tool()
def ida_defined_data() -> str:
    """Get all named data (excluding functions) like globals/constants."""
    return safe_post("defined_data", {})

@mcp.tool()
def ida_list_exports() -> str:
    """List all exported symbols from the binary."""
    return safe_post("list_exports", {})

@mcp.tool()
def ida_list_imports() -> str:
    """List all imported functions with addresses and ordinals."""
    return safe_post("list_imports", {})

@mcp.tool()
def ida_all_function_names() -> str:
    """Get all function names and their addresses."""
    return safe_post("get_all_function_names", {})

@mcp.tool()
def ida_search_functions_by_name(pattern: str) -> str:
    """Search all function names for a given substring."""
    return safe_post("search_functions_by_name", {"pattern": pattern})

@mcp.tool()
def ida_get_bytes_from_addr(address: str, size: int) -> str:
    """Read bytes from a specific memory address."""
    return safe_post("get_bytes_from_addr", {"address": address, "size": size})

@mcp.tool()
def ida_hex_to_int(n: str) -> str:
    """Convert a hex string address to an integer."""
    return safe_post("hex_address_to_int", {"n": n})

@mcp.tool()
def ida_get_screen_function() -> str:
    """Get the address of the function under the cursor."""
    return safe_post("get_screen_function", {})

@mcp.tool()
def ida_rename(ea: str, func_name: str) -> str:
    """Rename a function at a given address."""
    return safe_post("rename", {"ea": ea, "func_name": func_name})

@mcp.tool()
def ida_get_call_graph(func_ea: str, max_depth: int = 10) -> str:
    """Get the call graph leading to a given function."""
    return safe_post("get_call_graph", {"func_ea": func_ea, "max_depth": max_depth})

@mcp.tool()
def ida_get_function_usage(func_ea: str) -> str:
    """Find all places where a function is used."""
    return safe_post("get_function_usage", {"func_ea": func_ea})

@mcp.tool()
def ida_get_address_xrefs(ea: str) -> str:
    """Get all XREFs to and from a given address."""
    return safe_post("get_address_xrefs", {"ea": ea})

@mcp.tool()
def ida_get_decompiled_code(func_ea: str) -> str:
    """Get the decompiled pseudocode of a function."""
    return safe_post("get_decompiled_code", {"func_ea": func_ea})

@mcp.tool()
def ida_get_memory_mappings() -> str:
    """List all memory segments in the binary."""
    return safe_post("get_memory_mappings", {})

@mcp.tool()
def ida_search_strings(pattern: str) -> str:
    """Search for strings in the binary by pattern."""
    return safe_post("search_strings", {"pattern": pattern})


if __name__ == "__main__":
    mcp.run()
