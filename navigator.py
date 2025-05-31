"""
Navigator Plugin for IDA
Provides shortcuts to navigate between functions and data items
j - Jump to next function or data item
k - Jump to previous function or data item
"""

import ida_ida
import ida_kernwin
import ida_name
import idaapi
import idc

PLUGIN_NAME = "Navigator"
PLUGIN_VERSION = "1.3"
PLUGIN_COMMENT = __doc__.split('\n')[2]
PLUGIN_HELP = "j to go to next item, k to go to previous item"

ACTIONS = {
    "next_item": {
        "id": "idanav:next_item",
        "name": "Navigate to Next Item",
        "hotkey": "J",
        "tooltip": "Navigate to the next function or data item",
        "direction": "next",
    },
    "prev_item": {
        "id": "idanav:prev_item",
        "name": "Navigate to Previous Item",
        "hotkey": "K",
        "tooltip": "Navigate to the previous function or data item",
        "direction": "prev",
    },
}


class IDANavigator(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        """Initialize the plugin."""
        print(f"Initializing {PLUGIN_NAME} v{PLUGIN_VERSION}")
        for action_key, action_info in ACTIONS.items():
            if not self._register_action(action_info):
                print(f"[{PLUGIN_NAME}] Failed to register {action_key} hotkey")
                return idaapi.PLUGIN_SKIP
            idaapi.attach_action_to_menu("Edit/Other/", action_info["id"], idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def _register_action(self, action_info):
        handler = self.NavigationHandler(action_info["direction"])
        action_desc = idaapi.action_desc_t(action_info["id"], action_info["name"], handler, action_info["hotkey"], action_info["tooltip"])
        return idaapi.register_action(action_desc)

    def run(self, arg):
        for action_info in ACTIONS.values():
            idaapi.msg(f"[{PLUGIN_NAME}] Use {action_info['hotkey']!r} to move to {action_info['direction']!r} item.\n")

    def term(self):
        for action_info in ACTIONS.values():
            idaapi.unregister_action(action_info["id"])
        print(f"[{PLUGIN_NAME}] {PLUGIN_NAME} terminated")

    class NavigationHandler(idaapi.action_handler_t):
        def __init__(self, direction):
            idaapi.action_handler_t.__init__(self)
            self.direction = direction

        def activate(self, ctx):
            return IDANavigator.navigate_item(self.direction)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    @staticmethod
    def is_function_start(ea):
        """Check if the address is the start of a function."""
        func = idaapi.get_func(ea)
        return bool(func and func.start_ea == ea)

    @staticmethod
    def is_named_item(ea):
        """Check if the address contains a named item (variable, data, etc.)."""
        name = ida_name.get_name(ea)
        return bool(name and len(name) > 0 and not any(
            name.startswith(c) for c in ['loc_', 'locret', 'def_']
        ))

    @staticmethod
    def find_item(ea, direction="next") -> tuple[int, str]:
        """Find the next or previous named item or function start."""
        step = 1 if direction == "next" else -1
        max_ea = ida_ida.inf_get_max_ea()
        ptr = ea + step
        while 0 <= ptr < max_ea:
            if IDANavigator.is_function_start(ptr):
                return ptr, "function"
            if IDANavigator.is_named_item(ptr):
                return ptr, "data"
            ptr += step

        return idaapi.BADADDR, None

    @staticmethod
    def navigate_item(direction):
        """Navigate to the next or previous function or named item."""
        current_ea = idc.get_screen_ea()
        direction_str = "next" if direction == "next" else "previous"

        target_ea, item_type = IDANavigator.find_item(current_ea, direction)

        if target_ea == idaapi.BADADDR:
            idaapi.msg(f"No {direction_str} item found\n")
            return False

        idaapi.jumpto(target_ea, -1, ida_kernwin.UIJMP_ACTIVATE)
        target_name = ida_name.get_name(target_ea)
        if not target_name:
            target_name = f"unnamed_{item_type}"

        idaapi.msg(f"Navigated to {item_type}: {target_name} at {target_ea:#x}\n")
        return True


def PLUGIN_ENTRY():
    return IDANavigator()
