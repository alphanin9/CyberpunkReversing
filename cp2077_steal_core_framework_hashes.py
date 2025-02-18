import idc
import ida_segment
import ida_name

import json
import os

import re
import requests

"""
I regret nothing
"""

checked_mods = [
    ("RED4ext", "https://raw.githubusercontent.com/wopss/RED4ext/refs/heads/master/src/dll/Detail/AddressHashes.hpp"),
    ("RED4ext.SDK", "https://raw.githubusercontent.com/wopss/RED4ext.SDK/refs/heads/master/include/RED4ext/Detail/AddressHashes.hpp"),
    ("ArchiveXL", "https://raw.githubusercontent.com/psiberx/cp2077-archive-xl/refs/heads/main/src/Red/Addresses/Library.hpp"),
    ("Codeware", "https://raw.githubusercontent.com/psiberx/cp2077-codeware/refs/heads/main/src/Red/Addresses/Library.hpp"),
    ("TweakXL", "https://raw.githubusercontent.com/psiberx/cp2077-tweak-xl/refs/heads/master/src/Red/Addresses/Library.hpp"),
    ("RedHotTools", "https://raw.githubusercontent.com/psiberx/cp2077-red-hot-tools/refs/heads/master/src/Red/Addresses/Library.hpp"),
    ("CET", "https://raw.githubusercontent.com/maximegmd/CyberEngineTweaks/refs/heads/master/src/reverse/Addresses.h"),
    ("Sharedpunk", "https://raw.githubusercontent.com/alphanin9/SharedPunk/refs/heads/main/src/include/Impl/Detail/Hashes.hpp")
]

# Very hacky
# Better than pulling in libclang, though
hash_pattern = re.compile(".+ (.*) = (.+);") 

current_path = os.path.split(idc.get_idb_path())
address_path = os.path.join(current_path[0], "cyberpunk2077_addresses.json")

if not os.path.exists(address_path):
    raise "Failed to find address list! Are you sure you're reversing CP2077?"

address_map = {}

seg_code_start = ida_segment.get_segm_by_name(".text").start_ea
seg_data_start = ida_segment.get_segm_by_name(".data").start_ea
seg_rdata = ida_segment.get_segm_by_name(".idata")

if not seg_rdata:
    seg_rdata = ida_segment.get_segm_by_name(".rdata")

seg_rdata_start = seg_rdata.start_ea

with open(address_path) as file:
    address_list_json = json.load(file)

    for addy in address_list_json["Addresses"]:
        offset = addy["offset"].split(":")
        
        addrValue = int(offset[1], 16)
                
        final_addr = addrValue

        if offset[0] == "0001":
            final_addr = addrValue + seg_code_start
        elif offset[0] == "0002":
            final_addr = addrValue + seg_rdata_start
        elif offset[0] == "0003":
            final_addr = addrValue + seg_data_start
            
        address_map[int(addy["hash"])] = final_addr

stolen_hashes = 0

for mod_name, mod_address_hashes in checked_mods:
    hashes = requests.get(url=mod_address_hashes)
    matches = re.findall(hash_pattern, hashes.text)
    
    for hash_name, hash_shorthand in matches:
        parsed_hash = hash_shorthand
        
        if parsed_hash.lower().endswith("u"):
            parsed_hash = parsed_hash[:-1]
        elif parsed_hash.lower().endswith("ul"):
            parsed_hash = parsed_hash[:-2]
        
        as_integer = int(parsed_hash, base=0)
        
        if as_integer in address_map:
            name = ida_name.get_name(address_map[as_integer])

            if ida_name.is_uname(name):
                continue
            
            ida_name.set_name(address_map[as_integer], hash_name)
            
            stolen_hashes += 1
            print(f"Stole {hash_name} from {mod_name}")
            
print(f"Stole {stolen_hashes} hashes")
           
            