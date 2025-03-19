import idaapi
import idc
import idautils
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.calculator import CalculatorTools
from idatools import *
from prompts import default_prompt_zh

# Initialize Agno AI agent
agent = Agent(
    model=OpenAIChat(id="gpt-4o"),
    tools=[IdaTools()],
    description=default_prompt_zh,
    show_tool_calls=True,
    debug_mode=True,
    markdown=True
)

def suggest_function_name(func_ea):
    """Generate a suggested name for a function based on its characteristics."""
    func_name = idc.get_func_name(func_ea)
    if not func_name or func_name.startswith("sub_"):
        xrefs = list(idautils.CodeRefsTo(func_ea, 0))
        if xrefs:
            caller_name = idc.get_func_name(xrefs[0])
            if caller_name:
                new_name = f"{caller_name}_calls_{hex(func_ea)[2:]}"
                return new_name
        
        strings = list(idautils.Strings())
        for s in strings:
            if func_ea in idautils.DataRefsTo(s.ea):
                new_name = f"func_uses_{s}".replace(" ", "_")
                return new_name
    
    return None

def rename_function(func_ea):
    """Rename a function using the suggested name."""
    new_name = suggest_function_name(func_ea)
    if new_name:
        if idc.set_name(func_ea, new_name, idc.SN_NOWARN):
            print(f"[+] Renamed function at {hex(func_ea)} to {new_name}")
        else:
            print(f"[!] Failed to rename function at {hex(func_ea)}")
    else:
        print(f"[-] No suitable name found for function at {hex(func_ea)}")

def main():
    """Run the function renaming tool."""
    func_ea = idc.get_screen_ea()
    if idaapi.get_func(func_ea):
        rename_function(func_ea)
    else:
        print("[!] No function found at the current address.")

if __name__ == "__main__":
    main()
