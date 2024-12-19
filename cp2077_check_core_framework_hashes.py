import idautils
import ida_segment
import idc

import json
import os

import re
import requests

checked_mods = [
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

# We don't actually care about addy RVA I think, we just need to know if the address is present or not
present_addresses = set()

current_path = os.path.split(idc.get_idb_path())
address_path = os.path.join(current_path[0], "cyberpunk2077_addresses.json")

if not os.path.exists(address_path):
    raise "Failed to find address list! Are you sure you're reversing CP2077?"

with open(address_path) as file:
    address_list_json = json.load(file)

    for addy in address_list_json["Addresses"]:
        present_addresses.add(int(addy["hash"]))

errors = 0

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
        
        if as_integer not in present_addresses:
            print(f"{mod_name}: Failed to find {hash_name} hash! Old: {hash_shorthand}")
            errors += 1

if errors == 0:
    print("Good! No missing hashes were found in core frameworks!")
else:
    print(f"Oops, error count: {errors}")