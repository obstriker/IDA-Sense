import idaapi
import idautils
import idc
import json
import ida_funcs
import ida_bytes
import ida_segment
import ida_kernwin
import ida_hexrays
import ida_name
import threading
import uvicorn
from ida_kernwin import get_screen_ea
from fastapi import FastAPI
import functools
import queue

app = FastAPI()

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class IDASyncError(Exception):
    pass

class IDASafety:
    ida_kernwin.MFF_READ
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE

call_stack = queue.LifoQueue()

def sync_wrapper(ff, safety_mode: IDASafety):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    #logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode, ff.__name__)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = queue.Queue()

    def runned():
        #logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                'function {} from {}').format(ff.__name__, last_func_name)
            #logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()
            #logger.debug('Finished runned')

    ret_val = idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)
    return wrapper

@idaread
@app.get("/defined_data")
def defined_data() -> str:
    """
    Get all named data (excluding functions), like global variables or constants.

    Returns:
        str: JSON array of data names and addresses
    """
    data = []
    for ea, name in idautils.Names():
        try:
            if not ida_funcs.get_func(ea) and ("_imp" not in name):  # Correct usage: pass just the address
                data.append({"name": name, "ea": hex(ea)})
        except:
            pass
    return json.dumps({"operation": "defined_data", "result": data})

@idaread
@app.get("/list_exports")
def list_exports() -> str:
    """
    List all exported symbols using modern IDA API.

    Returns:
        str: JSON array of exported names, addresses, and ordinals
    """
    exports = []
    for ordinal, ea, name in idautils.Entries():
        exports.append({
            "name": name,
            "ea": hex(ea),
            "ordinal": ordinal
        })
    return json.dumps({"operation": "list_exports", "result": exports})

@idaread
@app.get("/list_imports")
def list_imports() -> str:
    """
    List all imported functions with module and name.

    Returns:
        str: JSON array of imported functions (module, function name, address)
    """
    imports = []

    def imp_cb(ea, name, ord):
        imports.append({
            "ea": hex(ea),
            "name": name,
            "ordinal": ord
        })
        return True

    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        name = idaapi.get_import_module_name(i) or f"module_{i}"
        idaapi.enum_import_names(i, lambda ea, func_name, ord: imp_cb(ea, func_name, ord))

    return json.dumps({"operation": "list_imports", "result": imports})

@idaread
@app.get("/get_all_function_names")
def get_all_function_names() -> str:
    """
    Get all function names and their start addresses.

    Returns:
        str: JSON object mapping function names to their addresses
    """
    funcs = {}
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        funcs[name] = hex(ea)
    return json.dumps({"operation": "get_all_function_names", "result": funcs})

@idaread
@app.post("/search_functions_by_name")
def search_functions_by_name(pattern: str) -> str:
    """
    Search all function names for a given substring.

    Args:
        pattern (str): Substring to search for in function names

    Returns:
        str: JSON list of function names and addresses matching the pattern
    """
    result = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if (pattern.lower() in name.lower()):
            result.append({"name": name, "ea": hex(ea)})

    return json.dumps({"operation": "search_functions", "result": result})

def read_until_xrefed_address() -> None:
    pass

@idaread
@app.post("/get_bytes_from_addr")
def get_bytes_from_addr(address: str, size: int) -> str:
    """
    Retrieve bytes from a specified memory address.
    Args:
        address (str): Hexadecimal address to read from
        size (int): Number of bytes to read

    Returns:
        str: JSON string containing the hexadecimal representation of the bytes
    """
    if isinstance(address, str):
        address = int(address, 16)

    data = ida_bytes.get_bytes(address, size).hex()
    return json.dumps({"operation": "get_bytes_from", "result": data})

def rename_local_variable(old_name: str, new_name: str) -> None:
    """
    Rename a local variable in the current pseudocode view.
    Args:
        old_name (str): Current name of the variable
        new_name (str): New name to assign to the variable

    Returns:
        None
    """
    widget = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            lvars = vu.cfunc.get_lvars()
            for lvar in lvars:
                if lvar.name == old_name:
                    if vu.rename_lvar(lvar, new_name, 1):
                        vu.refresh_ctext()
                        print(f"Renamed variable '{old_name}' to '{new_name}'.")
                    else:
                        print(f"Failed to rename variable '{old_name}' to '{new_name}'.")
                    break
            else:
                print(f"Variable '{old_name}' not found.")
        else:
            print("Failed to obtain vdui_t object.")
    else:
        print("The current widget is not a pseudocode view.")

@idaread
@app.get("/get_memory_mappings")
def get_memory_mappings() -> str:
    """
    Get information about all memory segments in the binary.
    Returns:
        str: JSON string containing segment information (name, start address, end address, size)
    """
    segments_list = []

    # Iterate over all segments
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg:
            seg_obj = {
                "name": ida_segment.get_segm_name(seg),
                "start": seg.start_ea,
                "end": seg.end_ea,
                "size": seg.end_ea - seg.start_ea
            }
            segments_list.append(seg_obj)
    return json.dumps({"operation": "get_memory_mappings", "result": segments_list})

@app.post("/hex_address_to_int")
def hex_address_to_int(n: str) -> int:
    """
    Args:
        n (str): Hexadecimal address string
    Returns:
        str: JSON string containing the integer representation of the address
    """
    return json.dumps({"operation": "conver_hex_to_int", "result": int(n, 16)})

@idaread
@app.get("/get_screen_function")
def get_screen_function() -> str:
    """
    Returns:
        str: JSON string containing the hexadecimal address of the current function
    """

    screen_function = ida_name.get_name_ea(0, idc.get_func_name(get_screen_ea()))
    return json.dumps({"operation": "get_memory_mappings", "result": hex(screen_function)})

@idawrite
@app.post("/rename")
def rename(ea: str, func_name: str) -> str:
    """
    Args:
        ea (str): Hexadecimal address of the function
        func_name (str): New name for the function

    Returns:
        str: JSON string containing the result status of the rename operation
    """
    if type(ea) is str:
        ea = int(ea, 16)

    try:
        dst_ea = ida_funcs.get_func(ea).start_ea
    except:
        dst_ea = ea
    res = idc.set_name(dst_ea, func_name, idc.SN_NOWARN)
    return json.dumps({"operation": "rename_function", "result": res})

@idaread
@app.post("/get_call_graph")
def get_call_graph(func_ea: str, visited=None, depth=0, max_depth=10):
    """
    Retrieve function call graph from root functions to a given function with depth limitation.
    Args:
        func_ea (str): Hexadecimal address of the target function
        visited (set, optional): Set of already visited function addresses
        depth (int, optional): Current recursion depth
        max_depth (int, optional): Maximum recursion depth to prevent infinite loops

    Returns:
        str: JSON string containing the call graph structure
    """
    if visited is None:
        visited = set()

    if type(func_ea) is str:
        func_ea = int(func_ea, 16)

    if func_ea in visited or depth >= max_depth:
        return []
    visited.add(func_ea)

    callers = []
    for xref in idautils.CodeRefsTo(func_ea, 0):
        func = idaapi.get_func(xref)
        if func and func.start_ea not in visited:
            callers.append({"addr": hex(xref), "name": idc.get_func_name(xref)})

            next_graph = get_call_graph(func.start_ea, visited, depth+1, max_depth)
            callers += json.loads(next_graph)["result"]

    return json.dumps({"operation": "get_call_graph", "result": callers})

@idaread
@app.post("/get_function_usage")
def get_function_usage(func_ea: str) -> str:
    """
    Find where the function is used in the binary, filtering duplicates.
    Args:
        func_ea (str): Hexadecimal address of the function ("0x123456")

    Returns:
        str: JSON string containing a list of Hexadecimal addresses that reference the function
    """
    refrences = []

    if type(func_ea) is str:
        func_ea = int(func_ea, 16)

    for addr in idautils.CodeRefsTo(func_ea, 0):
        refrences.append(hex(addr))

    return json.dumps({"operation": "get_function_usage", "result": refrences})

@idaread
@app.post("/get_address_xrefs")
def get_address_xrefs(ea: str) -> str:
    """
    Get all cross-references (XREFs) to and from a function, excluding self-references and intra-function references.
    Args:
        ea (str): Hexadecimal address to analyze
    Returns:
        str: JSON string containing a list of cross-reference Hexadecimal addresses
    """
    xrefs = []

    if isinstance(ea, str):
        ea = int(ea, 16)

    func = idaapi.get_func(ea)

    for xref in idautils.XrefsTo(ea):
        if xref.frm != ea and (not func or not func.contains(xref.frm)):
            xrefs.append(hex(xref.frm))

    for xref in idautils.XrefsFrom(ea, 0):
        if xref.to != ea and (not func or not func.contains(xref.to)):
            xrefs.append(hex(xref.to))

    return json.dumps({"operation": "get_xrefs", "result": list(set(xrefs))})

@idaread
@app.post("/get_decompiled_code")
def get_decompiled_code(func_ea: str) -> str:
    """
    Retrieve decompiled pseudocode for a given function as a text string with error handling.

    Args:
        func_ea (str): Hexadecimal address or integer address of the function

    Returns:
        str: JSON string containing the decompiled pseudocode or empty string if decompilation fails
    """
    try:
        if isinstance(func_ea, str):
            func_ea = int(func_ea, 16)
        if idaapi.init_hexrays_plugin():
            return json.dumps({"operation": "get_decompiled_code", "result": str(idaapi.decompile(func_ea))})
    except idaapi.DecompilationFailure as e:
        print(f"[!] Decompilation failed for function at {func_ea}: {e}")
    except Exception as e:
        print(f"[!] Unexpected error while decompiling {func_ea}: {e}")
    return json.dumps({"operation": "get_decompiled_code", "result": ""})

@idaread
@app.post("/search_strings")
def search_strings(pattern: str):
    """
    Search for strings in the binary matching a given pattern, case-insensitive.

    Args:
        pattern (str): String pattern to search for

    Returns:
        list: List of tuples containing (address, string value) for matches
    """
    results = []
    for s in idautils.Strings():
        if pattern.lower() in str(s).lower():
            results.append((s.ea, str(s)))
    return results

def start_api():
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="info")

def run():
    thread = threading.Thread(target=start_api, daemon=True)
    thread.start()

if __name__ == "__main__":
    run()
