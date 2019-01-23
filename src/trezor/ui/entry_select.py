from micropython import const

from trezor import loop, ui
from trezor.ui.button import BTN_CLICKED, Button

if False:
    from typing import Any  # noqa: F401

DEVICE = const(0)
HOST = const(1)


class EntrySelector(ui.Widget):
    def __init__(self, content: ui.Widget) -> None:
        self.content = content
        self.device = Button(ui.grid(8, n_y=4, n_x=4, cells_x=4), "Device")
        self.host = Button(ui.grid(12, n_y=4, n_x=4, cells_x=4), "Host")

    def taint(self) -> None:
        super().taint()
        self.device.taint()
        self.host.taint()

    def render(self) -> None:
        self.device.render()
        self.host.render()

    def touch(self, event: int, pos: ui.Pos) -> Any:
        if self.device.touch(event, pos) == BTN_CLICKED:
            return DEVICE
        if self.host.touch(event, pos) == BTN_CLICKED:
            return HOST

    async def __iter__(self) -> Any:
        return await loop.spawn(super().__iter__(), self.content)
