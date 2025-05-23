# Taken from: https://github.com/mrexodia/ida-pro-mcp

import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")
import re
import json
import struct
import threading
import http.server
from urllib.parse import urlparse
from typing import Any, Callable, get_type_hints, TypedDict, Optional, Annotated, TypeVar, Generic

class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data

class RPCRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}

    def register(self, func: Callable) -> Callable:
        self.methods[func.__name__] = func
        return func

    def dispatch(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JSONRPCError(-32601, f"Method '{method}' not found")

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(-32602, f"Invalid params: expected {len(hints)} arguments, got {len(params)}")

            # Validate and convert parameters
            converted_params = []
            for value, (param_name, expected_type) in zip(params, hints.items()):
                try:
                    if not isinstance(value, expected_type):
                        value = expected_type(value)
                    converted_params.append(value)
                except (ValueError, TypeError):
                    raise JSONRPCError(-32602, f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}")

            return func(*converted_params)
        elif isinstance(params, dict):
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(-32602, f"Invalid params: expected {list(hints.keys())}")

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                try:
                    if not isinstance(value, expected_type):
                        value = expected_type(value)
                    converted_params[param_name] = value
                except (ValueError, TypeError):
                    raise JSONRPCError(-32602, f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}")

            return func(**converted_params)
        else:
            raise JSONRPCError(-32600, "Invalid Request: params must be array or object")

rpc_registry = RPCRegistry()

def jsonrpc(func: Callable) -> Callable:
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)

class JSONRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code: int, message: str, id: Any = None):
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            }
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except json.JSONDecodeError:
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except IDAError as e:
            response["error"] = {
                "code": -32000,
                "message": e.message,
            }
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response).encode("utf-8")
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass

class MCPHTTPServer(http.server.HTTPServer):
    allow_reuse_address = False

class Server:
    HOST = "localhost"
    PORT = 13337

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False

    def start(self):
        if self.running:
            print("[MCP] Server Stopping")
            self.stop()
            return

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.running = True
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            # Create server in the thread to handle binding
            self.server = MCPHTTPServer((Server.HOST, Server.PORT), JSONRPCRequestHandler)
            print(f"[MCP] Server started at http://{Server.HOST}:{Server.PORT}")
            self.server.serve_forever()
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Port already in use (Linux/Windows)
                print("[MCP] Error: Port 13337 is already in use")
            else:
                print(f"[MCP] Server error: {e}")
            self.running = False
        except Exception as e:
            print(f"[MCP] Server error: {e}")
        finally:
            self.running = False

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging
import queue
import traceback
import functools

import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_gdl
import ida_lines
import ida_idaapi
import idc
import idaapi
import idautils
import ida_nalt
import ida_bytes
import ida_typeinf
import ida_xref
import ida_entry
import idautils

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class IDASyncError(Exception):
    pass

# Important note: Always make sure the return value from your function f is a
# copy of the data you have gotten from IDA, and not the original data.
#
# Example:
# --------
#
# Do this:
#
#   @idaread
#   def ts_Functions():
#       return list(idautils.Functions())
#
# Don't do this:
#
#   @idaread
#   def ts_Functions():
#       return idautils.Functions()
#

logger = logging.getLogger(__name__)

# Enum for safety modes. Higher means safer:
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
        logger.error(error_str)
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

def is_window_active():
    """Returns whether IDA is currently active"""
    try:
        from PyQt5.QtWidgets import QApplication
    except ImportError:
        return False

    app = QApplication.instance()
    if app is None:
        return False

    for widget in app.topLevelWidgets():
        if widget.isActiveWindow():
            return True
    return False

class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str

def get_image_size():
    try:
        # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida
        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    # Bad heuristic for image size (bad if the relocations are the last section)
    image_size = omax_ea - omin_ea
    # Try to extract it from the PE header
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size

@jsonrpc
@idaread
def get_metadata() -> Metadata:
    """
    Get metadata about the current IDB.

    Returns:
        Metadata: Dictionary containing information about the current binary file such as path, module name, base address, size, and various checksums.
    """
    return {
        "path": idaapi.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
        "size": hex(get_image_size()),
        "md5": ida_nalt.retrieve_input_file_md5().hex(),
        "sha256": ida_nalt.retrieve_input_file_sha256().hex(),
        "crc32": hex(ida_nalt.retrieve_input_file_crc32()),
        "filesize": hex(ida_nalt.retrieve_input_file_size()),
    }

def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    """
    Get the function prototype for a given function.
    
    Args:
        fn: The function to get the prototype for
        
    Returns:
        The function prototype as a string, or None if it couldn't be determined
    """
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None

class Function(TypedDict):
    address: str
    name: str
    size: str

def parse_address(address: str) -> int:
    """
    Parse a string representation of an address into an integer.
    
    Args:
        address: String representation of the address (e.g., "0x1234")
        
    Returns:
        The parsed address as an integer
        
    Raises:
        IDAError: If the address cannot be parsed
    """
    try:
        return int(address, 0)
    except ValueError:
        for ch in address:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {address}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {address}")

def get_function(address: int, *, raise_error=True) -> Function:
    """
    Get information about a function at the specified address.
    
    Args:
        address: The address of the function
        raise_error: If True, raise an error when the function is not found
        
    Returns:
        A dictionary containing the function's address, name, and size
        
    Raises:
        IDAError: If no function is found at the address and raise_error is True
    """
    fn = idaapi.get_func(address)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(address)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)
    return {
        "address": hex(fn.start_ea),
        "name": name,
        "size": hex(fn.end_ea - fn.start_ea),
    }

DEMANGLED_TO_EA = {}

def create_demangled_to_ea_map():
    """
    Create a mapping of demangled function names to their addresses.
    
    This populates the global DEMANGLED_TO_EA dictionary with demangled function names
    as keys and their corresponding addresses as values.
    """
    for ea in idautils.Functions():
        # Get the function name and demangle it
        # MNG_NODEFINIT inhibits everything except the main name
        # where default demangling adds the function signature
        # and decorators (if any)
        demangled = idaapi.demangle_name(
            idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea

@jsonrpc
@idaread
def get_function_by_name(
    name: Annotated[str, "Name of the function to get"]
) -> Function:
    """
    Retrieves a function's address by its name from the IDA database.
    
    Args:
        function_name (str): The name of the function to search for
        
    Returns:
        Optional[int]: The address of the function if found, None otherwise
    """
    function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
    if function_address == idaapi.BADADDR:
        # If map has not been created yet, create it
        if len(DEMANGLED_TO_EA) == 0:
            create_demangled_to_ea_map()
        # Try to find the function in the map, else raise an error
        if name in DEMANGLED_TO_EA:
            function_address = DEMANGLED_TO_EA[name]
        else:
            raise IDAError(f"No function found with name {name}")
    return get_function(function_address)

@jsonrpc
@idaread
def get_function_by_address(
    address: Annotated[str, "Address of the function to get"]
) -> Function:
    """
    Get a function by its address.
    
    Args:
        address: The address of the function
        
    Returns:
        Function: Information about the found function
    """
    return get_function(parse_address(address))

@jsonrpc
@idaread
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    
    Returns:
        str: The hexadecimal representation of the current address
    """
    return hex(idaapi.get_screen_ea())

@jsonrpc
@idaread
def get_current_function() -> Optional[Function]:
    """
    Get the function currently selected by the user.
    
    Returns:
        Optional[Function]: Information about the current function, or None if not in a function
    """
    return get_function(idaapi.get_screen_ea())

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

@jsonrpc
def convert_number(
    text: Annotated[str, "Textual representation of the number to convert"],
    size: Annotated[Optional[int], "Size of the variable in bytes"],
) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    try:
        value = int(text, 0)
    except ValueError:
        raise IDAError(f"Invalid number: {text}")

    # Estimate the size of the number
    if not size:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    # Convert the number to bytes
    try:
        bytes = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        raise IDAError(f"Number {text} is too big for {size} bytes")

    # Convert the bytes to ASCII
    ascii = ""
    for byte in bytes.rstrip(b"\x00"):
        if byte >= 32 and byte <= 126:
            ascii += chr(byte)
        else:
            ascii = None
            break

    return {
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": bytes.hex(" "),
        "ascii": ascii,
        "binary": bin(value)
    }

T = TypeVar("T")

class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]

def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    """
    Paginate a list of items.
    
    Args:
        data: The list to paginate
        offset: The starting index
        count: The number of items per page (0 means all remaining items)
        
    Returns:
        A dictionary containing the paginated data and the offset for the next page
    """
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset:offset+count],
        "next_offset": next_offset,
    }

@jsonrpc
@idaread
def list_exports(
        offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0x0,
        count: Annotated[int, "Number of imports to list (100 is a good default, 0 means remainder)"] = 10,
) -> str:
    """
    List all exported symbols using modern IDA API.

    Returns:
        str: JSON array of exported names, addresses, and ordinals
    """
    exports = []
    for export in idautils.Entries():
        _, ea, _, name = export
        exports.append({
            "name": name,
            "ea": hex(ea),
            # "ordinal": ordinal
        })

    return paginate(exports, offset, count)

@jsonrpc
@idaread
def list_imports(
        offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0x0,
        count: Annotated[int, "Number of imports to list (100 is a good default, 0 means remainder)"] = 10,
) -> str:
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
        })
        return True

    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        name = idaapi.get_import_module_name(i) or f"module_{i}"
        idaapi.enum_import_names(i, lambda ea, func_name, ord: imp_cb(ea, func_name, ord))

    return paginate(imports, offset, count)

@jsonrpc
@idaread
def get_bytes_from_addr(address: Annotated[str, "Address of address to read from"], size: Annotated[int, "Number of bytes to read"]) -> str:
    """
    Retrieve bytes from a specified memory address.
    Args:
        address (str): Hexadecimal address to read from
        size (int): Number of bytes to read

    Returns:
        Example: {"val": "0x112c00", "addr": "0xb1234", "label": "sub_112C00"}
        Wher val is the value in the memory, 
        addr is the address of the value,
        label is the name of the value
    """
    # if isinstance(address, str):
    #     address = int(address, 16)

    # data = ida_bytes.get_bytes(address, size).hex()
    # return ' '.join([data[i:i+2] for i in range(0, len(data), 2)])
    import ida_memory
    address = int(address, 16)
    
    memory_bytes = ida_memory.get_defined_bytes_from(address, size)
    memory_bytes = [vars(b) for b in memory_bytes]
    return memory_bytes

@jsonrpc
@idaread
def list_functions(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of functions to list (100 is a good default, 0 means remainder)"],
) -> Page[Function]:
    """
    List all functions in the database (paginated).
    
    Args:
        offset: The starting index for pagination
        count: The number of functions to return per page
        
    Returns:
        Page[Function]: Paginated list of functions
    """
    functions = [get_function(address) for address in idautils.Functions()]
    return paginate(functions, offset, count)

class String(TypedDict):
    address: str
    length: int
    type: str
    string: str

def get_strings() -> list[String]:
    """
    Get all strings found in the binary.
    
    Returns:
        A list of dictionaries containing information about each string
    """
    strings = []
    for item in idautils.Strings():
        string_type = "C" if item.strtype == 0 else "Unicode"
        try:
            string = str(item)
            if string:
                strings.append({
                    "address": hex(item.ea),
                    "length": item.length,
                    "type": string_type,
                    "string": string
                })
        except:
            continue
    return strings

@jsonrpc
@idaread
def list_strings(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """
    List all strings in the database (paginated).
    
    Args:
        offset: The starting index for pagination
        count: The number of strings to return per page
        
    Returns:
        Page[String]: Paginated list of strings
    """
    strings = get_strings()
    return paginate(strings, offset, count)

@jsonrpc
@idaread
def search_functions_by_name(pattern: str) -> str:
    """
    Search all function names for a given substring.

    Args:
        pattern (str): Substring to search for in function names (regex supported)

    Returns:
        str: JSON list of function names and addresses matching the pattern
    """
    result = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if (pattern.lower() in name.lower()):
            result.append({"name": name, "ea": hex(ea)})

    return json.dumps({"operation": "search_functions", "result": result})

@jsonrpc
@idaread
def search_strings(
        pattern_str: Annotated[str, "The regular expression to match((The generated regular expression includes case by default))"],
        offset: Annotated[int, "Offset to start listing from (start at 0)"],
        count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """
    Search for strings containing the given pattern (case-insensitive).
    
    Args:
        pattern: The substring to search for in strings
        offset: The starting index for pagination
        count: The number of strings to return per page
        
    Returns:
        Page[String]: Paginated list of matching strings
    """
    strings = get_strings()
    try:
        pattern = re.compile(pattern_str)
    except Exception as e:
        raise ValueError(f"Regular expression syntax error, reason is {e}")
    try:
        matched_strings = [s for s in strings if s["string"] and re.search(pattern, s["string"])]
    except Exception as e:
        raise ValueError(f"The regular match failed, reason is {e}")
    return paginate(matched_strings, offset, count)

@jsonrpc
@idaread
def search_strings(
    pattern: Annotated[str, "Substring to search for in strings"],
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """Search for strings containing the given pattern (case-insensitive)"""
    strings = get_strings()
    matched_strings = [s for s in strings if pattern.lower() in s["string"].lower()]
    return paginate(matched_strings, offset, count)



def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = idaapi.decompile(address)
    if not cfunc:
        message = f"Decompilation failed at {hex(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc

@jsonrpc
@idaread
def get_function_decompile(
    address: Annotated[str, "Address of the function to decompile"]
) -> str:
    """
    get Decompile psudo-code of a function at the given address. (address example: "0x12345678")
    
    Args:
        address: The address of the function to decompile
        
    Returns:
        str: The decompiled function pseudocode
    """
    address = parse_address(address)
    cfunc = decompile_checked(address)
    if is_window_active():
        ida_hexrays.open_pseudocode(address, ida_hexrays.OPF_REUSE)
    return str(idaapi.decompile(address))
    pseudocode = ""
    for i, sl in enumerate(sv):
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t()
        addr = None if i > 0 else cfunc.entry_ea
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            ds = item.dstr().split(": ")
            if len(ds) == 2:
                try:
                    addr = int(ds[0], 16)
                except ValueError:
                    pass
        line = ida_lines.tag_remove(sl.line)
        if len(pseudocode) > 0:
            pseudocode += "\n"
        if not addr:
            pseudocode += f"/* line: {i} */ {line}"
        else:
            pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"

    return pseudocode

def disassemble_function(
    start_address: Annotated[str, "Address of the function to disassemble"]
) -> str:
    """
    Disassembles an IDA function at the given address and returns its instructions.
    
    Args:
        function_address (int): The address of the function to disassemble
        with_comments (bool, optional): Whether to include comments in the 
                                      disassembly. Defaults to True.
        
    Returns:
        list[dict]: A list of dictionaries, each representing an instruction.
                   Each dictionary contains keys like 'address', 'mnemonic',
                   'operands', 'bytes', and optionally 'comment'.
    """
    start = parse_address(start_address)
    func = idaapi.get_func(start)
    if not func:
        raise IDAError(f"No function found containing address {start_address}")
    if is_window_active():
        ida_kernwin.jumpto(start)

    # TODO: add labels and limit the maximum number of instructions
    disassembly = ""
    for address in ida_funcs.func_item_iterator_t(func):
        if len(disassembly) > 0:
            disassembly += "\n"
        disassembly += f"{hex(address)}: "
        disassembly += idaapi.generate_disasm_line(address, idaapi.GENDSM_REMOVE_TAGS)
        comment = idaapi.get_cmt(address, False)
        if not comment:
            comment = idaapi.get_cmt(address, True)
        if comment:
            disassembly += f"; {comment}"
    return disassembly

class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]

def _get_xrefs_to(
    address: Annotated[str, "Address to get cross references to"]
) -> list[Xref]:
    """
    Gets all cross-references to the specified address (including data addresses) (hex address in string, example: "0x12345678").
    
    Args:
        address (int): The target address to find references to
        
    Returns:
        list[int]: A list of addresses that reference the target address
    """
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):
        xrefs.append({
            "address": hex(xref.frm),
            "type": "code" if xref.iscode else "data",
            "function": get_function(xref.frm, raise_error=False),
        })
    return xrefs


@jsonrpc
@idaread
def get_xrefs_to(
    address: Annotated[str, "Address to get cross references to"]
) -> list[Xref]:
    """
    Gets all cross-references to the specified address (including data addresses) (hex address in string, example: "0x12345678").
    
    Args:
        address (int): The target address to find references to
        
    Returns:
        list[int]: A list of addresses that reference the target address
    """
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):
        xrefs.append({
            "address": hex(xref.frm),
            "type": "code" if xref.iscode else "data",
            "function": get_function(xref.frm, raise_error=False),
        })
    return xrefs

@jsonrpc
@idaread
def get_entry_points(
        offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0x0,
        count: Annotated[int, "Number of imports to list (100 is a good default, 0 means remainder)"] = 30,
    ) -> list[Function]:
    """
    Get all entry points in the database.
    
    Returns:
        list[Function]: A list of functions that are entry points
    """
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        func = get_function(address, raise_error=False)
        if func is not None:
            result.append(func)

    return paginate(result, offset, count)


def _get_call_graph(
    func_ea: Annotated[str, "Hexadecimal address of the target function"],
    visited: Annotated[Optional[set], "Set of already visited function addresses"] = None,
    depth: Annotated[int, "Current recursion depth"] = 0,
    max_depth: Annotated[int, "Maximum recursion depth to prevent infinite loops"] = 5
) -> str:
    """
    Retrieve function call graph from root functions to a given function with depth limitation.
    (ONLY for functions)
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
    visited.add(hex(func_ea))

    callers = []
    for xref in _get_xrefs_to(hex(func_ea)):
        try:
            func = parse_address(xref["address"])
            func = idaapi.get_func(func)
            if func and func.start_ea not in visited:
                callers.append({"addr": hex(func.start_ea), "name": idc.get_func_name(func.start_ea)})
                next_graph = _get_call_graph(hex(func.start_ea), visited, depth+1, max_depth)
                callers += json.loads(next_graph)["result"]
        except:
            continue

    return json.dumps({"operation": "get_call_graph", "result": callers})


@jsonrpc
@idawrite
def get_call_graph(
    func_ea: Annotated[str, "Hexadecimal address of the target function"],
    visited: Annotated[Optional[set], "Set of already visited function addresses"] = None,
    depth: Annotated[int, "Current recursion depth"] = 0,
    max_depth: Annotated[int, "Maximum recursion depth to prevent infinite loops"] = 5
) -> str:
    return _get_call_graph(func_ea, visited, depth, max_depth)

@jsonrpc
@idawrite
def color_function(
    func_ea: Annotated[str, "Hex address of the function"],
    color: Annotated[str, "Hex RGB color (e.g. 0xFFAA00)"] = "0xAAFFAA"
) -> str:
    """
    Color all instructions in a given function.
    """
    try:
        func_ea = int(func_ea, 16)
        rgb_color = int(color, 16)

        func = idaapi.get_func(func_ea)
        if not func:
            return json.dumps({"error": "Invalid function address"})

        ea = func.start_ea
        while ea < func.end_ea:
            idaapi.set_item_color(ea, rgb_color)
            ea = idc.next_head(ea)

        return json.dumps({"status": "colored", "function": hex(func_ea), "color": color})
    except Exception as e:
        return json.dumps({"error": str(e)})

@jsonrpc
@idawrite
def reset_colored_functions() -> str:
    """
    Reset all custom colors in all functions.
    """
    count = 0

    for func in idautils.Functions():
        ea = func
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        while ea < end:
            if idaapi.get_item_color(ea) != 0xFFFFFFFF:
                idaapi.set_item_color(ea, 0xFFFFFFFF)
                count += 1
            ea = idc.next_head(ea)

    return json.dumps({"status": "reset", "instructions_cleared": count})

@jsonrpc
@idawrite
def set_comment(
    address: Annotated[str, "Address in the function to set the comment for"],
    comment: Annotated[str, "Comment text"]
):
    """Set a comment for a given address in the function disassembly and pseudocode"""
    address = parse_address(address)

    if not idaapi.set_cmt(address, comment, False):
        raise IDAError(f"Failed to set disassembly comment at {hex(address)}")

    # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
    # Check if the address corresponds to a line
    cfunc = decompile_checked(address)

    # Special case for function entry comments
    if address == cfunc.entry_ea:
        idc.set_func_cmt(address, comment, True)
        cfunc.refresh_func_ctext()
        return

    eamap = cfunc.get_eamap()
    if address not in eamap:
        print(f"Failed to set decompiler comment at {hex(address)}")
        return
    nearest_ea = eamap[address][0].ea

    # Remove existing orphan comments
    if cfunc.has_orphan_cmts():
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()

    # Set the comment by trying all possible item types
    tl = idaapi.treeloc_t()
    tl.ea = nearest_ea
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            return
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    print(f"Failed to set decompiler comment at {hex(address)}")

def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()

def refresh_decompiler_ctext(function_address: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
    if cfunc:
        cfunc.refresh_func_ctext()

@jsonrpc
@idawrite
def rename_local_variable(
    function_address: Annotated[str, "Address of the function containing the variable"],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"]
):
    """Rename a local variable in a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
        raise IDAError(f"Failed to rename local variable {old_name} in function {hex(func.start_ea)}")
    refresh_decompiler_ctext(func.start_ea)

@jsonrpc
@idawrite
def rename_global_variable(
    old_name: Annotated[str, "Current label of the global variable"],
    new_name: Annotated[str, "New name for the global variable (empty for a default name)"]
):
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError(f"Failed to rename global variable {old_name} to {new_name}")
    # refresh_decompiler_ctext(ea)

@jsonrpc
@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"]
):
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    if not tif:
        raise IDAError(f"Parsed declaration is not a variable type")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
        raise IDAError(f"Failed to apply type")

@jsonrpc
@idawrite
def rename_function(
    function_address: Annotated[str, "Address of the function to rename"],
    new_name: Annotated[str, "New name for the function (empty for a default name)"]
):
    """Rename a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not idaapi.set_name(func.start_ea, new_name):
        raise IDAError(f"Failed to rename function {hex(func.start_ea)} to {new_name}")
    refresh_decompiler_ctext(func.start_ea)

@jsonrpc
@idawrite
def set_function_prototype(
    function_address: Annotated[str, "Address of the function"],
    prototype: Annotated[str, "New function prototype"]
) -> str:
    """Set a function's prototype"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    try:
        tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
        if not tif.is_func():
            raise IDAError(f"Parsed declaration is not a function type")
        if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
            raise IDAError(f"Failed to apply type")
        refresh_decompiler_ctext(func.start_ea)
    except Exception as e:
        raise IDAError(f"Failed to parse prototype string: {prototype}")

class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvars):
        for lvar_saved in lvars.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False

# NOTE: This is extremely hacky, but necessary to get errors out of IDA
def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, str]:
    if sys.platform == "win32":
        import ctypes
        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages = []
        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        # NOTE: The approach above could also work on other platforms, but it's
        # not been tested and there are differences in the vararg ABIs.
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages

@jsonrpc
@idawrite
def declare_c_type(
    c_declaration: Annotated[str, "C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };"],
):
    """Create or update a local type from a C declaration"""
    # PT_SIL: Suppress warning dialogs (although it seems unnecessary here)
    # PT_EMPTY: Allow empty types (also unnecessary?)
    # PT_TYP: Print back status messages with struct tags
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
    errors, messages = parse_decls_ctypes(c_declaration, flags)

    pretty_messages = "\n".join(messages)
    if errors > 0:
        raise IDAError(f"Failed to parse type:\n{c_declaration}\n\nErrors:\n{pretty_messages}")
    return f"success\n\nInfo:\n{pretty_messages}"

@jsonrpc
@idawrite
def set_local_variable_type(
    function_address: Annotated[str, "Address of the function containing the variable"],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"]
):
    """Set a local variable's type"""
    try:
        new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    except Exception:
        raise IDAError(f"Failed to parse type: {new_type}")
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name):
        raise IDAError(f"Failed to find local variable: {variable_name}")
    modifier = my_modifier_t(variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func.start_ea, modifier):
        raise IDAError(f"Failed to modify local variable: {variable_name}")
    refresh_decompiler_ctext(func.start_ea)

def get_metadata() -> Metadata:
    """
    Get metadata about the current IDB.

    Returns:
        Metadata: Dictionary containing information about the current binary file such as path, module name, base address, size, and various checksums.
    """
    return {
        "path": idaapi.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
        "size": hex(get_image_size()),
        "md5": ida_nalt.retrieve_input_file_md5().hex(),
        "sha256": ida_nalt.retrieve_input_file_sha256().hex(),
        "crc32": hex(ida_nalt.retrieve_input_file_crc32()),
        "filesize": hex(ida_nalt.retrieve_input_file_size()),
    }
class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        self.server = Server()
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if sys.platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")
        print(f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server")
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        self.server.start()

    def term(self):
        self.server.stop()

def PLUGIN_ENTRY():
    return MCP()
