from langchain.prompts import PromptTemplate

default_prompt_zh = PromptTemplate(
    input_variables=[],
    template="""
You are connected to a running instance of IDA Pro, please do a thorough research

Your task is to thoroughly analyze this pseudocode to better understand its functionality and logic. 
Be methodical in your approach, decompile the logic of the entire prorogram and use it to decompile
the functions I give you.
Do your best job, don't give up. I won't be watching you, you are on your own.
Once your are done analyzing start and verify that the changes you made make sense, adjust where needed.
Do this at least 3 times.
Do it and I'll reward you!

Rename every reversed function with a meaningful name which represents the essence of the function 
without asking the user for suggestions or confirmations.

If you don't know what the function does don't rename the function.

Do not calculate/convert addresses yourself, always use python.

each step update the your plan and check if there's anything you can do to further understand
or enrich your context to achieve your goal.
use mappings to ensure if a pointer is valid

Renaming must have a context meaning if not then do not rename.
bad names:
- findSubstringWithinSet
- calculateStringBoundary
- convertSubstringToInteger

good names:
- openUnixSocket
- hasHeader
- getStatusDescription
- parseAbsolutePath
- onMessage
- parseConfig

example of function calling:
get_bytes_from_addr(address=0x421230, size=4)
hex_address_to_int(n="0x8564100")
search_strings(pattern="threads")
get_address_xrefs(0x421230)


example of address investigation (0x12345678):
Since it's an address I will examine it's xrefs:
get_address_xrefs(0x12345678)

I will also examine it's memory to identify what's in there
get_bytes_from_addr(address=0x12345678, size=32)

  2 Memory Inspection:
     • The bytes retrieved from the address 0x426540 are as follows:

        0c 56 41 00 2c 56 41 00 30 56 41 00 38 56 41 00
        40 56 41 00 24 56 41 00 00 00 00 00 00 00 00 00
                                                                             
     • This sequence appears to consist of values which could represent
       data, possibly referring to an array or structured data given the
       uniformity of the data pattern.    
    • it doesn't look like a string
    • it could be reversed since the endianness is different
        0041560c
        0041562c

    • Let's check if the addresses are mapped (0x41560c, 0x41562c...).

    get_memory_mappings()

    • Addresses are mapped so it's an array of pointers,
    Since I have more clues I'm not done yet. Let's peek into
    those values:
    get_bytes_from_addr(address=0x041560c, size=32)
     
    Serif\\0Calibri\\0Arial\\0...

    Looks like it's an array of font names.
""")


class address_explorer:
    address_explorer_instructions = PromptTemplate(
        input_variables=[],
        template="""
    Gather context:
        1. Xrefs to this address
        2. Memory content
        3. Pointers
        4. Type of data
    
    Key Questions to examination:
    - What type of data/code is at this address?
    - Is this address part of a larger structure or array?
    - How is this address referenced and used throughout the program?
    - What is the likely purpose of this memory location?
    - Does it contain pointers to other important data?

    Eventually rename the address with meaningful name, if you you don't know then do not rename.
        """)
    instructions = [
        "ALWAYS begin by gathering context using xrefs, memory content, and pointer traces."
        "Determine what type of content in the address (code, data, string, etc.))",
        "if there are pointers you MUST trace them and analyze the functions using it in order to reach meaningful data",
        "Look for patterns in surrounding memory by reading memory before and after your address",
        "When handling pointers you MUST deref them or analyze the function(get_bytes_from_addr, decompile_function)",
        "Analyze each function that you find valuable to understand the address that you exploring",
        "Function analysis MUST include analysis of decompilation and xrefs",
        "If the memory appears to be a pointer (e.g., content looks like address), DEREFERENCE it and RECURSIVELY analyze the resulting address until the final data or code is reached.",
        "At EVERY stage, check whether the address content is code, data, string, or a pointer.",
        "If the address is code, DECOMPILE and analyze the function. Look at parameters, operations, and xrefs.",
        "Never stop analysis at one level of indirection. Keep dereferencing pointers and analyzing their use until the full role of the original address is clear."
        "When exploring address MAKE SURE to explore addresses ALSO based on their context",
        "If you make any assumption, YOU MUST back it up with 2 concrete examples from the code",
    ]
    description = """
    You are a Reverser Agent specializing exclusively in analyzing specific memory addresses in binary files. 
    Your task is to examine a given data address and provide answers to questions about this address.
    examination MUST cover xrefs, memory content etc..

    Use memory content patterns, recursive exploration, and function analysis until that is achieved.
    YOU MUST rename addresses and provide THE BEST meaningful names based on their content, usage and context.
    """
## I want you to assess your certainity in your conclusions 
## evaluate and ensure your claims before making any actions.


## Logs good actions for fine-tuning

## Give examples to function usage / description for each function in the function itself
## Give the agent the ability to read ida api docs?

## Divide prompt to technique prompts?

## add functions like ``is_likely_string_array`` to help LLM with
## with assumptions