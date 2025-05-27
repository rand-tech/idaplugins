from __future__ import annotations

import os
import re
from typing import Dict, Iterable, Set, Tuple

from PyQt5 import QtCore, QtWidgets

import idaapi
import ida_kernwin
import idc
import idautils
import ida_funcs
import ida_name

_FILE_RE = re.compile(
    r"(?:[/\\][\w.-]+)*[/\\][\w.-]+\."
    r"(?:c|cp|cpp|cxx|cc|h|hh|hpp|rs|py|java|mm|m|swift|swiftc|o)"
    r"(?:\:\d+)?",
    re.IGNORECASE,
)
_AVOID = ("https://", "http://", ".apple.com/")


def extract_source_strings() -> Dict[int, str]:
    return {
        s.ea: m.group()
        for s in idautils.Strings()
        if (m := _FILE_RE.search(str(s))) and not any(b in str(s) for b in _AVOID)
    }


def _xrefs(ea: int, depth: int, max_depth: int, seen: set[int]) -> Iterable[int]:
    if depth > max_depth or ea in seen:
        return
    seen.add(ea)
    for xr in idautils.XrefsTo(ea):
        if xr.iscode and (fn := ida_funcs.get_func(xr.frm)):
            yield fn.start_ea
        else:
            yield from _xrefs(xr.frm, depth + 1, max_depth, seen)


def build_function_source_map(max_depth: int = 2) -> Dict[int, Set[str]]:
    mapping: Dict[int, Set[str]] = {}
    for str_ea, path in extract_source_strings().items():
        for f_ea in _xrefs(str_ea, 0, max_depth, set()):
            mapping.setdefault(f_ea, set()).add(path)
    return mapping


def is_user_func(ea: int) -> bool:
    fn = ida_funcs.get_func(ea)
    if not fn:
        return False
    fl = idc.get_func_flags(ea)
    return not (fl & ida_funcs.FUNC_LIB or fl & ida_funcs.FUNC_THUNK or idc.get_segm_name(fn.start_ea) == "extern")


def nice_name(ea: int) -> str:
    raw = ida_funcs.get_func_name(ea)
    return ida_name.demangle_name(raw, idc.INF_LONG_DN) or raw


class SourceTree(QtWidgets.QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(("Source File / Function", "Address"))
        self.setColumnWidth(0, 320)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu)
        self.itemDoubleClicked.connect(self._dbl)

    def populate(self, mapping: Dict[int, Set[str]]):
        self.clear()
        root: Dict[str, dict | list[Tuple[str, int]]] = {}

        for ea in idautils.Functions():
            if not is_user_func(ea):
                continue
            for p in mapping.get(ea, {"<unknown>"}):
                # parts = re.split(r"[\\/]+", p)#.lstrip("\\/"))
                parts = p.strip().split(os.sep)
                cur = root
                for part in parts[:-1]:
                    cur = cur.setdefault(part, {})
                cur.setdefault(parts[-1], []).append((nice_name(ea), ea))

        self._add_nodes(self.invisibleRootItem(), root)
        self.sortItems(0, QtCore.Qt.AscendingOrder)

    def _add_nodes(self, parent, node):
        if isinstance(node, dict):
            for k, v in node.items():
                it = QtWidgets.QTreeWidgetItem(parent, [k])
                self._add_nodes(it, v)
        else:
            for n, ea in node:
                child = QtWidgets.QTreeWidgetItem(parent, [n, f"{ea:#x}"])
                child.setData(0, QtCore.Qt.UserRole, ea)

    def _dbl(self, item, _col):
        if ea := item.data(0, QtCore.Qt.UserRole):
            idc.jumpto(int(ea))

    def _ctx_menu(self, pos):
        it = self.itemAt(pos)
        if not it or not it.data(0, QtCore.Qt.UserRole):
            return
        m = QtWidgets.QMenu(self)
        m.addAction("Copy", lambda: QtWidgets.QApplication.clipboard().setText(f"{it.text(0)} {it.text(1)}"))
        m.addAction("Jump to function", lambda: idc.jumpto(it.data(0, QtCore.Qt.UserRole)))
        m.exec_(self.viewport().mapToGlobal(pos))

    def apply_filter(self, text: str):
        t = text.lower()

        def rec(node):
            vis = t in node.text(0).lower() or t in node.text(1).lower()
            for i in range(node.childCount()):
                vis |= rec(node.child(i))
            node.setHidden(not vis)
            return vis

        for i in range(self.invisibleRootItem().childCount()):
            rec(self.invisibleRootItem().child(i))


class ViewerForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        w = self.FormToPyQtWidget(form)
        lay = QtWidgets.QVBoxLayout(w)
        self._search = QtWidgets.QLineEdit(placeholderText="Search...")
        self._tree = SourceTree()
        lay.addWidget(self._search)
        lay.addWidget(self._tree)
        self._search.textChanged.connect(self._tree.apply_filter)

        # ida_kernwin.show_wait_box("Building source-file map...\n")
        mapping = build_function_source_map()
        # ida_kernwin.hide_wait_box()
        self._tree.populate(mapping)

    def OnClose(self, _): pass
    def Show(self): return ida_kernwin.PluginForm.Show(self, "Source File Viewer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class _Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = help = "Display functions grouped by source file"
    wanted_name = "Source File Viewer"
    wanted_hotkey = "Ctrl-Alt-S"
    _form: ViewerForm | None = None

    def init(self): return idaapi.PLUGIN_OK
    def run(self, _): self._show()
    def term(self): self._form = None
    def _show(self):
        if self._form is None:
            self._form = ViewerForm()
        self._form.Show()

def PLUGIN_ENTRY():
    return _Plugin()


if __name__ == "__main__":
    ViewerForm().Show()
