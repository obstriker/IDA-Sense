import idaapi
import idautils
import idc
from agno.tools import Toolkit
import json
import ida_funcs
import ida_bytes
import ida_segment
import ida_kernwin
import ida_hexrays
from ida_kernwin import get_screen_ea

# Add descriptions for each function to help the agent understand

class IdaTools(Toolkit):
    def __init__(self):
        super().__init__(name="ida_tools")

        self.register(self.get_call_graph)
        self.register(self.get_function_usage)
        self.register(self.get_address_xrefs)
        self.register(self.get_decompiled_code)
        self.register(self.search_strings)
        self.register(self.get_function_args)
        self.register(self.rename_function)
        self.register(self.get_screen_function)
        self.register(self.hex_address_to_int)
        self.register(self.get_bytes_from_addr)
        self.register(self.get_memory_mappings)

    # TODO: suggest a better name
    def get_bytes_from_addr(self, address: str, size: int):
        if type(address) is str:
            address = int(address, 16)
            
        data = ida_bytes.get_bytes(address, size).hex()
        return json.dumps({"operation": "get_bytes_from", "result": data})

    # TODO: add convertion to strings, to int, to hex etc..
    # Basic utils for the agent to understand bytes
    # it can be running python commands too.

    # TODO: untested
    def rename_local_variable(old_name, new_name):
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

    def get_memory_mappings(self):
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

    def hex_address_to_int(self, n: str):
        return json.dumps({"operation": "conver_hex_to_int", "result": int(n, 16)})

    def get_screen_function(self):
        return json.dumps({"operation": "get_screen_function", "result": hex(get_screen_ea())})

    def rename_function(self, ea: str, func_name: str):

        if type(ea) is str:
            ea = int(ea, 16)

        func_ea = ida_funcs.get_func(ea).start_ea
        res = idc.set_name(func_ea, func_name, idc.SN_NOWARN)
        return json.dumps({"operation": "rename_function", "result": res})

    def get_call_graph(self, func_ea: str, visited=None, depth=0, max_depth=10):
        """Retrieve function call graph from root functions to a given function with depth limitation."""
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
                callers.append((xref, self.get_call_graph(func.start_ea, visited, depth+1, max_depth)))
        return json.dumps({"operation": "get_call_graph", "result": callers})

    def get_function_usage(self, func_ea: str):
        """Find where the function is used in the binary, filtering duplicates."""
        if type(func_ea) is str:
            func_ea = int(func_ea, 16)

        return json.dumps({"operation": "get_function_usage", "result": list(set(idautils.CodeRefsTo(func_ea, 0)))})

    def get_address_xrefs(self, ea: str):
        """Get all cross-references (XREFs) to and from a function, excluding self-references and intra-function references."""
        xrefs = []
        func = idaapi.get_func(ea)
        
        if ea is str:
            ea = int(ea, 16)

        for xref in idautils.XrefsTo(ea):
            if xref.frm != ea and (not func or not func.contains(xref.frm)):
                xrefs.append(xref.frm)
        
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.to != ea and (not func or not func.contains(xref.to)):
                xrefs.append(xref.to)
        
        return json.dumps({"operation": "get_xrefs", "result": list(set(xrefs))})

    def get_decompiled_code(self, func_ea):
        """Retrieve decompiled pseudocode for a given function as a text string with error handling."""
        try:
            if type(func_ea) is str:
                func_ea = int(func_ea, 16)
            print(func_ea)
            print(type(func_ea))
            
            if idaapi.init_hexrays_plugin():
                return json.dumps({"operation": "get_decompiled_code", "result": str(idaapi.decompile(func_ea))})
        except idaapi.DecompilationFailure as e:
            print(f"[!] Decompilation failed for function at {func_ea}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error while decompiling {func_ea}: {e}")
        return json.dumps({"operation": "get_decompiled_code", "result": ""})

    def search_strings(self, pattern: str):
        """Search for strings in the binary matching a given pattern, case-insensitive."""
        results = []
        for s in idautils.Strings():
            if pattern.lower() in str(s).lower():
                results.append((s.ea, str(s)))
        return results

    def get_function_args(self, func_ea: str):
        """Retrieve function argument count and types if available."""
        args = []

        if type(func_ea) is str:
            func_ea = int(func_ea, 16)

        tinfo = idaapi.tinfo_t()
        if idaapi.get_tinfo(tinfo, func_ea):
            func_type_data = idaapi.func_type_data_t()
            if tinfo.get_func_details(func_type_data):
                args = [(arg.name, str(arg.type)) for arg in func_type_data]
        return json.dumps({"operation": "get_function_args", "result": args})