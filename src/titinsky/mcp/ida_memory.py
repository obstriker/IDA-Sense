import idc
import idautils
import idaapi
import ida_xref
import ida_funcs
import ida_segment

from typing import TypedDict, Optional

class Function(TypedDict):
    address: str
    name: str
    size: str

class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class IDASyncError(Exception):
    pass

# Classes from earlier (you can place these at the top of your script)
class MemoryEntry:
    def __init__(self, val, addr, label=None, xrefs=None):
        if isinstance(addr, int):
            addr = hex(addr)
        if isinstance(val, int):
            val = hex(val)
            
        self.val = val
        self.addr = addr
        self.label = label
        self.xrefs = xrefs

    def __str__(self):

        if self.label is None or self.label == "":
            return f"{self.__class__.__name__.lower()}(val={self.val}, addr={self.addr}, xrefs={self.xrefs})"
        return f"{self.__class__.__name__.lower()}(val={self.val}, label=\"{self.label}\", addr={self.addr}, xrefs={self.xrefs})"

class db(MemoryEntry): pass
class dw(MemoryEntry): pass
class dd(MemoryEntry): pass
class dq(MemoryEntry): pass

# Add string, data pointer classes so that the LLM will understand that it's not a function

class struct:
    def __init__(self, name, address, fields):
        self.name = name
        self.address = address
        self.fields = fields

    def __str__(self):
        inner = ",\n    ".join(str(f) for f in self.fields)
        return f'struct(name="{self.name}", address=0x{self.address:X}, fields=[\n    {inner}\n])'

    def __repr__(self):
        return str(self)

class array:
    def __init__(self, type_str, values, label, address):
        self.type = type_str
        self.values = values
        self.label = label or ""
        self.address = address

    def __str__(self):
        hex_vals = ", ".join(hex(v) for v in self.values)
        return f'array(type="{self.type}", count={len(self.values)}, values=[{hex_vals}], label="{self.label}", address=0x{self.address:X})'

    def __repr__(self):
        return str(self)

# 🧠 Main function to use in IDA
def get_defined_bytes_from(addr, size=64, collapse_arrays=False):
    result = []
    end = addr + size
    ea = addr

    def get_label(val):
        name = idc.get_name(val)
        return name if name else ""

    while ea < end:
        flags = idc.get_full_flags(ea)
        item_size = idc.get_item_size(ea)
        label = idc.get_name(ea)
        xrefs = len(get_xrefs_to(hex(ea)))

        segment = ida_segment.get_segm_name(ida_segment.getseg(ea))

        if item_size == 0:
            val = idc.get_wide_byte(ea)
            result.append(db(val=val, label=label, addr=segment + ":" + str(ea), xrefs=xrefs))
            ea += 1
            continue

        if item_size == 1:
            val = idc.get_wide_byte(ea)
            result.append(db(val=val, label=label, addr=segment + ":" + hex(ea),xrefs=xrefs))
        elif item_size == 2:
            val = idc.get_wide_word(ea)
            result.append(dw(val=val, label=label, addr=segment + ":" + hex(ea), xrefs=xrefs))
        elif item_size == 4:
            val = idc.get_wide_dword(ea)
            label_str = get_label(val) or label
            result.append(dd(val=val, label=label_str, addr=segment + ":" + hex(ea), xrefs=xrefs))
        elif item_size == 8:
            val = idc.get_qword(ea)
            label_str = get_label(val) or label
            result.append(dq(val=val, label=label_str, addr=segment + ":" + hex(ea), xrefs=xrefs))
        else:
            val = idc.get_wide_byte(ea)
            result.append(db(val=val, label=label, addr=segment + ":" + hex(ea), xrefs=xrefs))

        ea += item_size

    if collapse_arrays:
        result = collapse_into_arrays(result)

    return result

# Optional: Collapse consecutive entries of the same type into array()
def collapse_into_arrays(entries, min_group_size=3):
    collapsed = []
    group = []
    last_type = None

    def flush_group():
        if len(group) >= min_group_size:
            values = [e.val for e in group]
            collapsed.append(array(type_str=group[0].__class__.__name__.lower(), values=values, label=group[0].label, address=group[0].addr))
        else:
            collapsed.extend(group)
        group.clear()

    for entry in entries:
        if last_type == entry.__class__:
            group.append(entry)
        else:
            flush_group()
            group = [entry]
            last_type = entry.__class__

    flush_group()
    return str(collapsed)

def get_xrefs_to(address: str
) -> list[Xref]:
    """
    Gets all cross-references to the specified address (hex address in string, example: "0x12345678").
    
    Args:
        address (int): The target address to find references to
        
    Returns:
        list[int]: A list of addresses that reference the target address
    """

    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):
        try:
            xrefs.append({
                "address": hex(xref.frm),
                "type": "code" if xref.iscode else "data",
                "function": get_function(xref.frm, raise_error=False),
            })
        except:
            continue
    return xrefs

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
        return int(address, 16)
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