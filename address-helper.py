VERSION = '1.0.0'
__AUTHOR__ = "not_alphanine"

PLUGIN_NAME = "Get Cyberpunk 2077 address hashes"

import os
import sys
import idc
import idaapi
import idautils
import ida_funcs
import ida_name
import ida_ua
import ida_segment

import json

import ida_ida
UA_MAXOP=ida_ida.UA_MAXOP

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

idaver_74newer = (major == 7 and minor >= 4)
idaver_8newer = (major >= 8)

if idaver_74newer or idaver_8newer:
    newer_version_compatible = True
else:
    newer_version_compatible = False

if newer_version_compatible:
    #IDA 7.4+
    #https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
    import ida_ida
    import ida_kernwin

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication

def set_clipboard_text(data):
    cb = QApplication.clipboard()
    cb.clear(mode=cb.Clipboard )
    cb.setText(data, mode=cb.Clipboard)

class CP2077AddressHelper(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Get address hash of function/vtable"
    help = "Select whatever line you want (with functions) or the vtable, right click and press \"Lookup hash\""
    wanted_name = PLUGIN_NAME
    
    ACTION_LOOKUP_HASH = "prefix:cp2077_lookup_hash"
    ACTION_JUMP_TO_HASH = "prefix:cp2077_jump_to_hash"

    def init_action_lookup_hash(self):
        if idaapi.unregister_action(self.ACTION_LOOKUP_HASH):
            idaapi.msg("Warning: action was already registered, unregistering it first\n")
        
        if idaapi.unregister_action(self.ACTION_JUMP_TO_HASH):
            idaapi.msg("Warning: action was already registered, unregistering it first\n")

        if (sys.version_info > (3, 0)):
            # Describe the action using python3 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_LOOKUP_HASH,                                                    # The action name.
                "Lookup CP2077 address hash",                                               # The action text.
                IDACtxEntry(lookup_current_address_hash),                                   # The action handler.
            )

            action_jump_desc = idaapi.action_desc_t(
                self.ACTION_JUMP_TO_HASH,
                "Jump to CP2077 addr hash",
                IDACtxEntry(goto_hash)
            )
        else:
            # Describe the action using python2 copy
            action_desc = idaapi.action_desc_t(
                self.ACTION_LOOKUP_HASH,                                        # The action name.
                "Lookup CP2077 address hash",                                   # The action text.
                IDACtxEntry(lookup_current_address_hash),                      # The action handler.
            )

            action_jump_desc = idaapi.action_desc_t(
                self.ACTION_JUMP_TO_HASH,
                "Jump to CP2077 addr hash",
                IDACtxEntry(goto_hash)
            )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"
        assert idaapi.register_action(action_jump_desc), "Action 2 registration failed"

    def del_action_lookup_hash(self):
        idaapi.unregister_action(self.ACTION_LOOKUP_HASH)
        idaapi.unregister_action(self.ACTION_JUMP_TO_HASH)

    def init(self):
        if idc.get_root_filename() != "Cyberpunk2077.exe":
            # This is only for CP2077
            return idaapi.PLUGIN_SKIP

        self.init_action_lookup_hash()
        self._init_hooks()

        idaapi.msg("%s started" % self.wanted_name)

        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        if hasattr(self, '_hooks'):
            self._hooks.unhook()
        self.del_action_lookup_hash()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    def _init_hooks(self):
        self._hooks = PluginHooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    

class PluginHooks(idaapi.UI_Hooks):
    def __init__(self):
        # Call the __init__ method of the superclass
        super(PluginHooks, self).__init__()

        # Get the IDA version
        major, minor = map(int, idaapi.get_kernel_version().split("."))
        self.newer_version_compatible = (major == 7 and minor >= 4) or (major >= 8)
        
        # If the IDA version is less than 7.4, define finish_populating_tform_popup
        if not self.newer_version_compatible:
            self.finish_populating_tform_popup = self._finish_populating_tform_popup

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """
        A right click menu is about to be shown. (IDA 7.x)
        """
        inject_lookup_address_hash(widget, popup_handle, idaapi.get_widget_type(widget))
        return 0


    def _finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_lookup_address_hash(form, popup, idaapi.get_tform_type(form))
        return 0
    
    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            idaapi.attach_action_to_popup(
                form,
                popup,
                CP2077AddressHelper.ACTION_LOOKUP_HASH,
                "Lookup CP2077 address hash",
                idaapi.SETMENU_APP
            )

            idaapi.attach_action_to_popup(
                form,
                popup,
                CP2077AddressHelper.ACTION_JUMP_TO_HASH,
                "Jump to CP2077 address hash",
                idaapi.SETMENU_APP
            )

        # done
        return 0
    
def inject_lookup_address_hash(widget, popup_handle, widget_type):
    disasm_type = None
    if major > 8:
        disasm_type = idaapi.BWN_DISASM
    else:
        disasm_type = idaapi.BWN_DISASMS

    if widget_type == disasm_type or widget_type == idaapi.BWN_PSEUDOCODE:
        idaapi.attach_action_to_popup(
            widget,
            popup_handle,
            CP2077AddressHelper.ACTION_LOOKUP_HASH,
            "Lookup CP2077 address hash",
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_popup(
            widget,
            popup_handle,
            CP2077AddressHelper.ACTION_JUMP_TO_HASH,
            "Jump to CP2077 address hash",
            idaapi.SETMENU_APP
        )
    return 0

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return CP2077AddressHelper()

cp2077_addresses_cache = None

def build_address_cache():
    global cp2077_addresses_cache

    # Build address cache first...
    if cp2077_addresses_cache is None:
        print("Building addr cache...")
        current_path = os.path.split(idc.get_idb_path())
        address_path = os.path.join(current_path[0], "cyberpunk2077_addresses.json")

        print("File is at ", current_path)

        cp2077_addresses_cache = {}

        addr_to_hash = {}
        hash_to_addr = {}

        if not os.path.exists(address_path):
            print("Failed to find CP2077 addresses!")
            return
        
        with open(address_path) as file:
            # Note: it being obsolete does not matter here! We'll be fine anyway
            base_of_code = ida_segment.getnseg(1).start_ea
            base_of_rdata = ida_segment.getnseg(2).start_ea
            base_of_data = ida_segment.getnseg(4).start_ea

            # 1 = code
            # 2 = rdata
            # 3 = data

            json_addresses = json.load(file)["Addresses"]
            addr_count = 0
            for addr in json_addresses:
                offset = addr["offset"].split(":")

                # 1st: seg
                # 2nd: addr

                addrValue = int(offset[1], 16)
                
                final_addr = addrValue

                if offset[0] == "0001":
                    final_addr = addrValue + base_of_code
                elif offset[0] == "0002":
                    final_addr = addrValue + base_of_rdata
                elif offset[0] == "0003":
                    final_addr = addrValue + base_of_data

                # Maybe make a pass that renames autonamed functions with defined syms to their names in the .json...

                if "symbol" in addr:
                    func_start = idc.get_func_attr(final_addr, idc.FUNCATTR_START)
                    func_name = idc.get_func_name(func_start)

                    if func_name.startswith("sub_"):
                        # Automatically named, rename it?
                        idaapi.set_name(func_start, addr["symbol"], idaapi.SN_FORCE)
                    else:
                        print(f'{addr["symbol"]}@{hex(final_addr)} = {func_name}')

                if not (final_addr in addr_to_hash):
                    addr_to_hash[final_addr] = []

                addr_to_hash[final_addr].append(addr["hash"])
                
                hash_to_addr[int(addr["hash"])] = final_addr

                addr_count += 1
            print(f"Loaded {addr_count} addresses into map")

            cp2077_addresses_cache["hash_to_addr"] = hash_to_addr
            cp2077_addresses_cache["addr_to_hash"] = addr_to_hash

def get_hash_for_address(addr):
    global cp2077_addresses_cache
    build_address_cache()

    if addr in cp2077_addresses_cache["addr_to_hash"]:
        return cp2077_addresses_cache["addr_to_hash"][addr]
    
    return None

def get_addr_for_hash(hash):
    global cp2077_addresses_cache
    build_address_cache()

    if hash in cp2077_addresses_cache["hash_to_addr"]:
        return cp2077_addresses_cache["hash_to_addr"][hash]

    return None


def lookup_current_address_hash():
    """
    If we're reversing CP2077, tries to get the address hash of the current fn and put it in clipboard/output
    """

    screen_address = idc.get_screen_ea()

    if screen_address != idaapi.BADADDR:
        addr_to_look_for = screen_address
        func_start = idc.get_func_attr(screen_address, idc.FUNCATTR_START)
        if func_start != idaapi.BADADDR:
            addr_to_look_for = func_start

        addr_hash = get_hash_for_address(addr_to_look_for)

        if addr_hash:
            if len(addr_hash) > 1:
                print("Multiple hashes!")
                for i in range(len(addr_hash)):
                    print(i, ": ", addr_hash[i])
                set_clipboard_text(addr_hash[0])
            else:
                print("Hash:", addr_hash[0])
                set_clipboard_text(addr_hash[0])
        else:
            print("Failed to find address in cache!")

def goto_hash():
    hash_str = None
    if newer_version_compatible:
        hash_str = ida_kernwin.ask_str("0", 0, "Hash to jump towards")    
    else:
        hash_str = idc.AskStr("0", "Hash to jump towards")

    if not hash_str:
        return
    
    hash_int = int(hash_str, 0)

    addr = get_addr_for_hash(hash_int)

    if not addr:
        print("Failed to find addy for hash!")
        return
    
    if newer_version_compatible:
        ida_kernwin.jumpto(addr)
    else:
        idc.Jump(addr)
        
class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS