from trezor import ui

if False:
    from typing import Any  # noqa: F401


class Container(ui.Widget):
    def __init__(self, *children: ui.Widget) -> None:
        self.children = children

    def taint(self) -> None:
        super().taint()
        for child in self.children:
            child.taint()

    def render(self) -> None:
        for child in self.children:
            child.render()

    def touch(self, event: int, pos: ui.Pos) -> Any:
        for child in self.children:
            result = child.touch(event, pos)
            if result is not None:
                return result
