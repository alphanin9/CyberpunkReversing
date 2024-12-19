# Some scripts for Cyberpunk 2077 reverse engineering

Mostly made for personal use. Have some neat features and should work on Patch 2.2.

### Address helper

- Helps get address hashes and jump to them

### Find all RTTI types

- Helps with reversing classes that have RTTI definition 
- Renames them + their ctors + their vtables + their type object

### Core framework hash checker

- Checks if address hashes used in core frameworks are present in current CP2077 version, whines if they're not
- Currently checks for ArchiveXL, Codeware, TweakXL, RedHotTools, CET, RED4ext SDK and my shared library for my mods

Credits to [@cra0](https://github.com/cra0) for his [RVA finder](https://github.com/cra0/ida-scripts) that I used as a "base" for hacking together the address hash helper.
Shoutout to [@psiberx](https://github.com/psiberx) as well for giving some hints on the RTTI type finder.