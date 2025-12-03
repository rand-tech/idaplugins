from collections.abc import Callable
from dataclasses import dataclass

import ida_idaapi
import ida_kernwin
import idaapi
import idautils
import idc
from PySide6 import QtCore, QtGui, QtWidgets

_PLUGIN_NAME = "icp"

_RECENT_USAGE: dict[str, int] = {}
_RECENT_COUNTER = 0
_ACTIVE_DIALOG: "PaletteDialog | None" = None

UI_COLORS = {
    "bg": "#1e1e1e",
    "fg": "#e7e7e7",
    "border": "#3c3c3c",
    "hover_border": "#454545",
    "focus_border": "#0e639c",
    "selection_bg": "#264f78",
    "selection_fg": "#ffffff",
    "list_bg": "#252526",
    "list_hover": "#2a2d2e",
    "list_selected": "#094771",
    "shortcut_bg": "#3c3c3c",
    "shortcut_border": "#505050",
    "shortcut_text": "#e7e7e7",
}


@dataclass
class Action:
    name: str
    handler: Callable[["Action"], None]
    id: str
    shortcut: str = ""
    description: str = ""
    color: str | None = None


@dataclass
class Palette:
    title: str
    placeholder: str
    entries: list[Action]
    prefix_sources: dict[str, Callable[[], list[Action]]] | None = None
    default_prefix: str | None = None


_ACTION_REGISTRY: dict[str, Action] = {}


def _remember_actions(actions: list[Action]) -> None:
    for action in actions:
        _ACTION_REGISTRY[action.id] = action


def _set_active_dialog(dialog: "PaletteDialog") -> None:
    global _ACTIVE_DIALOG
    if _ACTIVE_DIALOG is not None and _ACTIVE_DIALOG is not dialog:
        try:
            _ACTIVE_DIALOG.close()
        except Exception:
            pass
    _ACTIVE_DIALOG = dialog


def _clear_active_dialog(dialog: "PaletteDialog") -> None:
    global _ACTIVE_DIALOG
    if _ACTIVE_DIALOG is dialog:
        _ACTIVE_DIALOG = None


def fuzzy_score(needle: str, haystack: str) -> int:
    tokens = [t for t in needle.lower().split() if t]
    if not tokens:
        return 0

    haystack = haystack.lower()
    total_score = 0
    last_pos = -1

    for token in tokens:
        pos_sum = 0
        pos = last_pos
        for ch in token:
            idx = haystack.find(ch, pos + 1)
            if idx == -1:
                return 10**9
            pos_sum += idx
            pos = idx
        total_score += pos_sum
        last_pos = pos

    return total_score


def _dialog_stylesheet() -> str:
    return f"""
    QDialog {{ background-color: {UI_COLORS["bg"]}; color: {UI_COLORS["fg"]}; }}
    """


def _line_edit_stylesheet() -> str:
    return f"""
    QLineEdit {{
        background: {UI_COLORS["bg"]};
        color: {UI_COLORS["fg"]};
        border: 1px solid {UI_COLORS["border"]};
        border-radius: 2px;
        selection-background-color: {UI_COLORS["selection_bg"]};
        selection-color: {UI_COLORS["selection_fg"]};
    }}
    QLineEdit:focus {{ border: 1px solid {UI_COLORS["focus_border"]}; }}
    QLineEdit:hover {{ border: 1px solid {UI_COLORS["hover_border"]}; }}
    """


def _list_stylesheet() -> str:
    return f"""
    QListWidget {{
        background: {UI_COLORS["list_bg"]};
        color: {UI_COLORS["fg"]};
        border: 1px solid {UI_COLORS["border"]};
        outline: 0;
    }}
    QListWidget::item {{ padding: 3px 8px; }}
    QListWidget::item:selected {{ background: {UI_COLORS["list_selected"]}; color: {UI_COLORS["selection_fg"]}; }}
    QListWidget::item:hover {{ background: {UI_COLORS["list_hover"]}; }}
    """


class PaletteDialog(QtWidgets.QDialog):
    def __init__(self, palette: Palette, parent=None):
        super().__init__(parent)
        self._palette = palette
        self._all_actions = palette.entries[:]
        self._prefix_sources = dict(palette.prefix_sources or {})
        self._prefix_cache: dict[str, list[Action]] = {}
        self._default_prefix = palette.default_prefix
        if self._default_prefix is None and self._prefix_sources:
            self._default_prefix = next(iter(self._prefix_sources))
        self._active_prefix = self._default_prefix
        _remember_actions(self._all_actions)

        self.setWindowTitle(palette.title)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowType.Tool | QtCore.Qt.WindowType.FramelessWindowHint)

        self.setStyleSheet(_dialog_stylesheet())
        self.setMinimumWidth(720)

        self._edit = QtWidgets.QLineEdit(self)
        self._edit.setPlaceholderText(palette.placeholder)
        self._edit.setFocus(QtCore.Qt.FocusReason.ActiveWindowFocusReason)
        self._edit.setTextMargins(8, 6, 8, 6)
        self._edit.setMinimumHeight(self._edit.fontMetrics().height() + 12)
        self._edit.setAttribute(QtCore.Qt.WidgetAttribute.WA_MacShowFocusRect, True)
        self._edit.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self._edit.setStyleSheet(_line_edit_stylesheet())

        self._list = QtWidgets.QListWidget(self)
        self._list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self._list.setUniformItemSizes(True)
        self._list.setAlternatingRowColors(True)
        self._list.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setTextElideMode(QtCore.Qt.TextElideMode.ElideRight)
        self._list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._list.setMouseTracking(True)
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.setFocusProxy(self._edit)
        self._list.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self._list.setStyleSheet(_list_stylesheet())
        self._list.setItemDelegate(PaletteItemDelegate(self._list))

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        top_row = QtWidgets.QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        top_row.addWidget(self._edit, 1)
        layout.addLayout(top_row)
        layout.addWidget(self._list)

        initial_actions = self._actions_for_prefix(self._active_prefix) if self._prefix_sources else self._all_actions
        self._rebuild_list("", initial_actions)

        self._app = QtWidgets.QApplication.instance()
        self._app.installEventFilter(self)

        self._edit.installEventFilter(self)
        self._list.installEventFilter(self)
        self._edit.textChanged.connect(self._on_text_changed)
        self._list.itemActivated.connect(self._on_item_activated)
        self._edit.returnPressed.connect(lambda: self._activate_item(self._list.currentItem()))

        shortcut_context = QtCore.Qt.ShortcutContext.WidgetWithChildrenShortcut
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Down), self, activated=lambda: self._move_selection(1), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Up), self, activated=lambda: self._move_selection(-1), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Modifier.META.value | QtCore.Qt.Key.Key_N.value), self, activated=lambda: self._move_selection(1), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Modifier.META.value | QtCore.Qt.Key.Key_P.value), self, activated=lambda: self._move_selection(-1), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_PageDown), self, activated=lambda: self._move_selection(7), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_PageUp), self, activated=lambda: self._move_selection(-7), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Return), self, activated=lambda: self._activate_item(self._list.currentItem()), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Enter), self, activated=lambda: self._activate_item(self._list.currentItem()), context=shortcut_context)
        QtGui.QShortcut(QtGui.QKeySequence(QtCore.Qt.Key.Key_Escape), self, activated=self.reject, context=shortcut_context)

    def _rebuild_list(self, keyword: str, actions: list[Action]) -> None:
        self._list.clear()
        scored: list[tuple[int, int, int, Action]] = []
        for idx, a in enumerate(actions):
            score = fuzzy_score(keyword, a.name)
            if score >= 10**9:
                continue
            recency = self._recency_rank(a)
            scored.append((score, -recency, idx, a))

        if not scored:
            return

        scored.sort()

        recent_ids = {a.id for a in self._recent_actions(limit=20)}
        recent_items = [(s, r, i, a) for (s, r, i, a) in scored if a.id in recent_ids]
        other_items = [(s, r, i, a) for (s, r, i, a) in scored if a.id not in recent_ids]
        ordered_items = recent_items + other_items

        def _add_action_item(action: Action) -> None:
            text = action.name if not action.shortcut else f"{action.name}\t{action.shortcut}"
            item = QtWidgets.QListWidgetItem(text)
            if action.color:
                item.setData(QtCore.Qt.ItemDataRole.ForegroundRole, QtGui.QColor(action.color))
            if action.description:
                item.setToolTip(action.description)
            item.setData(QtCore.Qt.ItemDataRole.UserRole, action)
            item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, action.id in recent_ids)
            self._list.addItem(item)

        first_selectable_row: int | None = None
        for _s, _r, _i, action in ordered_items:
            if first_selectable_row is None:
                first_selectable_row = self._list.count()
            _add_action_item(action)

        if first_selectable_row is not None and self._list.count() > 0:
            self._list.setCurrentRow(first_selectable_row)
            self._list.scrollToItem(self._list.currentItem(), QtWidgets.QAbstractItemView.ScrollHint.PositionAtTop)

    def _on_text_changed(self, text: str) -> None:
        keyword = text
        actions = self._all_actions

        if self._prefix_sources:
            prefix_char = text[0] if text else None
            if prefix_char and prefix_char in self._prefix_sources:
                self._active_prefix = prefix_char
                keyword = text[1:].lstrip()
            else:
                self._active_prefix = self._default_prefix
                keyword = text.lstrip()

            actions = self._actions_for_prefix(self._active_prefix)

        self._rebuild_list(keyword, actions)

    def _activate_item(self, item: QtWidgets.QListWidgetItem | None) -> None:
        if item is None:
            return
        action: Action = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if action is None:
            return
        try:
            action.handler(action)
        except Exception as exc:
            import traceback
            import sys as _sys

            _sys.stderr.write(f"[command palette] handler error: {exc}\n")
            traceback.print_exc()
        self._mark_recent(action.id)
        self.accept()

    def _on_item_activated(self, item: QtWidgets.QListWidgetItem) -> None:
        self._activate_item(item)

    def keyPressEvent(self, event):  # type: ignore[override]
        key = event.key()
        if key in (QtCore.Qt.Key.Key_Return, QtCore.Qt.Key.Key_Enter):
            self._activate_item(self._list.currentItem())
            event.accept()
            return
        if key in (QtCore.Qt.Key.Key_Up, QtCore.Qt.Key.Key_Down):
            self._move_selection(-1 if key == QtCore.Qt.Key.Key_Up else 1)
            event.accept()
            return
        if key == QtCore.Qt.Key.Key_Escape:
            self.reject()
            event.accept()
            return
        super().keyPressEvent(event)

    def showEvent(self, event):  # type: ignore[override]
        super().showEvent(event)
        self._edit.setFocus(QtCore.Qt.FocusReason.ActiveWindowFocusReason)
        self._edit.selectAll()

    def eventFilter(self, obj, event):  # type: ignore[override]
        if event.type() == QtCore.QEvent.Type.KeyPress:
            key = event.key()

            if obj is self._edit and key in (QtCore.Qt.Key.Key_Up, QtCore.Qt.Key.Key_Down):
                self._move_selection(-1 if key == QtCore.Qt.Key.Key_Up else 1)
                event.accept()
                return True

            if obj is self._edit and key in (QtCore.Qt.Key.Key_Return, QtCore.Qt.Key.Key_Enter):
                self._activate_item(self._list.currentItem())
                event.accept()
                return True

            if obj is self._edit and key == QtCore.Qt.Key.Key_Escape:
                self.reject()
                event.accept()
                return True

            if obj is self._list:
                if event.text() or key in (QtCore.Qt.Key.Key_Backspace, QtCore.Qt.Key.Key_Delete):
                    self._edit.setFocus(QtCore.Qt.FocusReason.OtherFocusReason)
                    QtWidgets.QApplication.sendEvent(self._edit, event)
                    event.accept()
                    return True

                if key in (QtCore.Qt.Key.Key_Return, QtCore.Qt.Key.Key_Enter):
                    self._activate_item(self._list.currentItem())
                    event.accept()
                    return True

                if key == QtCore.Qt.Key.Key_Escape:
                    self.reject()
                    event.accept()
                    return True

            if self.isVisible():
                if key in (QtCore.Qt.Key.Key_Up, QtCore.Qt.Key.Key_Down):
                    self._move_selection(-1 if key == QtCore.Qt.Key.Key_Up else 1)
                    event.accept()
                    return True
                if key in (QtCore.Qt.Key.Key_Return, QtCore.Qt.Key.Key_Enter):
                    self._activate_item(self._list.currentItem())
                    event.accept()
                    return True
                if key == QtCore.Qt.Key.Key_Escape:
                    self.reject()
                    event.accept()
                    return True

        return super().eventFilter(obj, event)

    def _move_selection(self, delta: int) -> None:
        if self._list.count() == 0:
            return
        current = self._list.currentRow()
        new_row = max(0, min(self._list.count() - 1, current + delta))
        self._list.setCurrentRow(new_row)
        item = self._list.item(new_row)
        if item is not None:
            self._list.setCurrentItem(item)
            self._list.scrollToItem(item, QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter)

    def closeEvent(self, event):  # type: ignore[override]
        try:
            if hasattr(self, "_app"):
                self._app.removeEventFilter(self)
        except Exception:
            pass
        super().closeEvent(event)

    def _actions_for_prefix(self, prefix: str | None) -> list[Action]:
        if not self._prefix_sources or prefix is None or prefix not in self._prefix_sources:
            return self._all_actions

        if prefix not in self._prefix_cache:
            try:
                self._prefix_cache[prefix] = self._prefix_sources[prefix]() or []
            except Exception:
                self._prefix_cache[prefix] = []
        actions = self._prefix_cache[prefix]
        _remember_actions(actions)
        return actions

    def _recency_rank(self, action: Action) -> int:
        return _RECENT_USAGE.get(action.id, -1)

    def _mark_recent(self, action_id: str) -> None:
        global _RECENT_COUNTER
        _RECENT_COUNTER += 1
        _RECENT_USAGE[action_id] = _RECENT_COUNTER

    def _recent_actions(self, limit: int = 20) -> list[Action]:
        if not _RECENT_USAGE:
            return []

        recent: list[Action] = []
        for action_id, _counter in sorted(_RECENT_USAGE.items(), key=lambda kv: kv[1], reverse=True):
            action = _ACTION_REGISTRY.get(action_id)
            if action is None:
                continue
            recent.append(action)
            if len(recent) >= limit:
                break
        return recent


class PaletteItemDelegate(QtWidgets.QStyledItemDelegate):
    """Custom painter to mimic VS Code command palette rows."""

    def __init__(self, parent=None):
        super().__init__(parent)
        base_font = QtWidgets.QApplication.font()

        self._name_font = QtGui.QFont(base_font)
        self._name_font.setPointSizeF(self._name_font.pointSizeF() + 1)

        self._shortcut_font = QtGui.QFont(base_font)
        self._shortcut_font.setPointSizeF(max(self._shortcut_font.pointSizeF() - 1, 8))
        self._shortcut_font.setWeight(QtGui.QFont.Weight.DemiBold)

        self._colors = {
            "bg": QtGui.QColor(UI_COLORS["list_bg"]),
            "hover": QtGui.QColor(UI_COLORS["list_hover"]),
            "selected": QtGui.QColor(UI_COLORS["list_selected"]),
            "text": QtGui.QColor(UI_COLORS["fg"]),
            "text_selected": QtGui.QColor(UI_COLORS["selection_fg"]),
            "shortcut_bg": QtGui.QColor(UI_COLORS["shortcut_bg"]),
            "shortcut_border": QtGui.QColor(UI_COLORS["shortcut_border"]),
            "shortcut_text": QtGui.QColor(UI_COLORS["shortcut_text"]),
        }

    def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionViewItem, index):  # type: ignore[override]
        action = index.data(QtCore.Qt.ItemDataRole.UserRole)
        if action is None:
            super().paint(painter, option, index)
            return
        is_recent = bool(index.data(QtCore.Qt.ItemDataRole.UserRole + 1))
        explicit_color = index.data(QtCore.Qt.ItemDataRole.ForegroundRole)

        rect = option.rect
        state = option.state
        is_selected = bool(state & QtWidgets.QStyle.StateFlag.State_Selected)
        is_hover = bool(state & QtWidgets.QStyle.StateFlag.State_MouseOver)

        bg = self._colors["selected"] if is_selected else self._colors["hover"] if is_hover else self._colors["bg"]
        text_color = self._colors["text_selected"] if is_selected else self._colors["text"]

        painter.save()
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(rect, bg)

        padding_x = 12
        padding_y = 6
        inner_rect = rect.adjusted(padding_x, padding_y, -padding_x, -padding_y)

        shortcut_tokens = self._split_shortcut_tokens(getattr(action, "shortcut", ""))
        shortcut_width = self._shortcut_width(shortcut_tokens)
        recent_width = self._badge_width(self._shortcut_font, "recently used") if is_recent else 0
        spacing = 6 if shortcut_width and recent_width else 0
        reserved_width = shortcut_width + recent_width + spacing
        text_rect = QtCore.QRect(inner_rect)
        if reserved_width:
            text_rect.setRight(inner_rect.right() - reserved_width - 8)

        name_metrics = QtGui.QFontMetrics(self._name_font)
        elided_name = name_metrics.elidedText(str(getattr(action, "name", "")), QtCore.Qt.TextElideMode.ElideRight, text_rect.width())
        painter.setFont(self._name_font)
        painter.setPen(QtGui.QColor(explicit_color) if explicit_color else text_color)
        painter.drawText(text_rect, QtCore.Qt.AlignmentFlag.AlignVCenter | QtCore.Qt.AlignmentFlag.AlignLeft, elided_name)

        x_cursor = inner_rect.right()
        center_y = inner_rect.center().y()

        if is_recent:
            badge_width = self._badge_width(self._shortcut_font, "recently used")
            badge_height = self._badge_height(self._shortcut_font)
            x_cursor -= badge_width
            badge_rect = QtCore.QRect(x_cursor, center_y - badge_height // 2, badge_width, badge_height)
            self._draw_badge(painter, badge_rect, "recently used", is_selected)
            x_cursor -= spacing

        if shortcut_tokens:
            self._draw_shortcuts(painter, inner_rect, shortcut_tokens, is_selected, x_cursor)

        painter.restore()

    def sizeHint(self, option, index):  # type: ignore[override]
        metrics = QtGui.QFontMetrics(self._name_font)
        return QtCore.QSize(0, metrics.height() + 16)

    def _split_shortcut_tokens(self, shortcut: str) -> list[str]:
        shortcut = shortcut.strip()
        if not shortcut:
            return []
        shortcut = shortcut.replace(" ", "")
        return [token for token in shortcut.split("+") if token]

    def _shortcut_width(self, tokens: list[str]) -> int:
        if not tokens:
            return 0
        fm = QtGui.QFontMetrics(self._shortcut_font)
        total = 0
        for token in tokens:
            token_width = fm.horizontalAdvance(token)
            total += token_width + 12
        total += max(0, (len(tokens) - 1) * 6)
        return total

    def _badge_width(self, font: QtGui.QFont, text: str) -> int:
        fm = QtGui.QFontMetrics(font)
        token_width = fm.horizontalAdvance(text)
        return token_width + 12

    def _badge_height(self, font: QtGui.QFont) -> int:
        fm = QtGui.QFontMetrics(font)
        return fm.height() + 6

    def _draw_badge(self, painter: QtGui.QPainter, rect: QtCore.QRect, text: str, is_selected: bool) -> None:
        radius = 4
        painter.setBrush(self._colors["shortcut_bg"])
        painter.setPen(QtGui.QPen(self._colors["shortcut_border"], 1))
        painter.drawRoundedRect(rect, radius, radius)

        painter.setFont(self._shortcut_font)
        painter.setPen(self._colors["shortcut_text"] if not is_selected else self._colors["text_selected"])
        painter.drawText(rect, QtCore.Qt.AlignmentFlag.AlignCenter, text)

    def _draw_shortcuts(self, painter: QtGui.QPainter, rect: QtCore.QRect, tokens: list[str], is_selected: bool, x_cursor: int) -> None:
        fm = QtGui.QFontMetrics(self._shortcut_font)
        x = x_cursor
        center_y = rect.center().y()

        for token in reversed(tokens):
            token_width = fm.horizontalAdvance(token)
            badge_width = token_width + 12
            badge_height = fm.height() + 6
            x -= badge_width
            badge_rect = QtCore.QRect(x, center_y - badge_height // 2, badge_width, badge_height)

            self._draw_badge(painter, badge_rect, token, is_selected)
            x -= 6


# Public API
def show_palette(palette: Palette) -> None:
    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication([])

    parent = QtWidgets.QApplication.activeWindow()
    dlg = PaletteDialog(palette, parent=parent)
    dlg.resize(760, 520)
    dlg.finished.connect(lambda _result, d=dlg: _clear_active_dialog(d))
    dlg.setModal(False)
    dlg.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)
    dlg.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose, True)
    _set_active_dialog(dlg)
    dlg.show()
    dlg.raise_()
    dlg.activateWindow()
    dlg._edit.setFocus(QtCore.Qt.FocusReason.ActiveWindowFocusReason)


# Action builders


def build_command_actions() -> list[Action]:
    actions: list[Action] = []
    registered = ida_kernwin.get_registered_actions()

    for name in registered:
        label = (ida_kernwin.get_action_label(name) or name).replace("~", "")
        tooltip = ida_kernwin.get_action_tooltip(name) or ""
        shortcut = ida_kernwin.get_action_shortcut(name) or ""

        def handler_factory(action_name: str):
            def _handler(_action: Action) -> None:
                ida_kernwin.process_ui_action(action_name)

            return _handler

        actions.append(
            Action(
                name=label,
                handler=handler_factory(name),
                id=name,
                shortcut=shortcut,
                description=tooltip,
            )
        )
    return actions


def build_string_actions() -> list[Action]:
    actions: list[Action] = []
    strings_iter = idautils.Strings()

    for s in strings_iter:
        text = str(s)
        ea = int(s.ea)
        display = text.encode("unicode_escape").decode("ascii")

        def handler_factory(addr: int, preview: str):
            def _handler(_action: Action) -> None:
                idc.jumpto(addr)
                ida_kernwin.msg(f"[{_PLUGIN_NAME}] jumped to string @ {hex(addr)}: {preview}\n")

            return _handler

        actions.append(
            Action(
                name=display,
                handler=handler_factory(ea, display),
                id=f"{_PLUGIN_NAME}:string:{ea:x}",
                description=f"{display} @ {hex(ea)}",
                color="#8CC84F",
            )
        )
    return actions


def build_function_actions() -> list[Action]:
    actions: list[Action] = []
    funcs = list(idautils.Functions())

    for ea in funcs:
        name = idc.get_func_name(ea)
        display = name

        def handler_factory(addr: int, func_name: str):
            def _handler(_action: Action) -> None:
                idc.jumpto(addr)
                ida_kernwin.msg(f"[{_PLUGIN_NAME}] jumped to function @ {hex(addr)}: {func_name}\n")

            return _handler

        actions.append(
            Action(
                name=display,
                handler=handler_factory(ea, display),
                id=f"{_PLUGIN_NAME}:function:{ea:x}",
                description=f"{display} @ {hex(ea)}",
                color="#FFD200",
            )
        )
    return actions


def build_name_actions() -> list[Action]:
    actions: list[Action] = []
    names_iter = list(idautils.Names())

    for ea, name in names_iter:
        display = name

        def handler_factory(addr: int, sym_name: str):
            def _handler(_action: Action) -> None:
                idc.jumpto(addr)
                ida_kernwin.msg(f"[{_PLUGIN_NAME}] jumped to name @ {hex(addr)}: {sym_name}\n")

            return _handler

        actions.append(
            Action(
                name=display,
                handler=handler_factory(ea, display),
                id=f"{_PLUGIN_NAME}:name:{ea:x}",
                description=f"{display} @ {hex(ea)}",
                color="#FFECBB",
            )
        )
    return actions


def build_struct_actions() -> list[Action]:
    actions: list[Action] = []
    structs_iter = list(idautils.Structs())

    for entry in structs_iter:
        if isinstance(entry, tuple):
            if len(entry) == 2:
                sid, name = entry
            elif len(entry) >= 3:
                _idx, sid, name = entry[0], entry[1], entry[2]
            else:
                continue
        else:
            continue

        sname = name or f"struct_{sid:x}"

        def handler_factory(struct_id: int, struct_name: str):
            def _handler(_action: Action) -> None:
                idc.jumpto(idc.get_struc_id(struct_name))

            return _handler

        actions.append(
            Action(
                name=sname,
                handler=handler_factory(sid, sname),
                id=f"{_PLUGIN_NAME}:struct:{sid:x}",
                description=f"Structure {sname}",
            )
        )

        members = list(idautils.StructMembers(sid))
        for member_entry in members:
            if not isinstance(member_entry, tuple) or len(member_entry) < 2:
                continue
            offset, mname = member_entry[0], member_entry[1]
            if not mname:
                continue

            def member_handler_factory(struct_id: int, member_name: str, member_off: int, struct_name: str):
                def _handler(_action: Action) -> None:
                    mid = idc.get_member_id(struct_id, member_off)
                    print(f"{type(struct_id)=} {struct_id=} {type(mid)=} {mid=} {type(member_off)=} {member_off=}")
                    idc.jumpto(struct_id)
                    idc.jumpto(mid)  # TODO: sid is supported, mid is not. IDAPython fun moment :(

                return _handler

            display = f"{sname}.{mname}"
            actions.append(
                Action(
                    name=display,
                    handler=member_handler_factory(sid, mname, offset, sname),
                    id=f"{_PLUGIN_NAME}:structmember:{sid:x}:{offset:x}",
                    description=f"{display} @ +0x{offset:x}",
                )
            )

    return actions


def _launcher_sources():
    return {
        ">": build_command_actions,
        "$": build_string_actions,
        "@": build_function_actions,
        "#": build_name_actions,
        "!": build_struct_actions,
    }


def show_command_palette() -> None:
    palette = Palette(
        title=f"{_PLUGIN_NAME} - Commands",
        placeholder=r"Type > for commands, @ for functions, # for names, $ for strings, ! for structs",
        entries=[],
        prefix_sources=_launcher_sources(),
        default_prefix=">",
    )
    show_palette(palette)


class _IcpCommandHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):  # type: ignore[override]
        show_command_palette()
        return 1

    def update(self, ctx):  # type: ignore[override]
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class icp_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "IDA command palette"
    help = "Meta+Shift+P for commands"
    wanted_name = "command_palette"
    wanted_hotkey = "Meta+Shift+P"

    def init(self):
        if not idaapi.is_idaq():
            return idaapi.PLUGIN_SKIP
        desc_cmd = ida_kernwin.action_desc_t(f"{_PLUGIN_NAME}:commands", "IDA Command palette", _IcpCommandHandler(), "Meta+Shift+P", "Search IDA commands", -1)
        ida_kernwin.register_action(desc_cmd)
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        show_command_palette()

    def term(self):
        ida_kernwin.unregister_action(f"{_PLUGIN_NAME}:commands")


def PLUGIN_ENTRY():
    return icp_plugin_t()
