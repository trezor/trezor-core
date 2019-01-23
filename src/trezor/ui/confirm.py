from micropython import const

from trezor import loop, res, ui
from trezor.ui.button import BTN_ACTIVE, BTN_CLICKED, Button
from trezor.ui.loader import Loader

if __debug__:
    from apps.debug import confirm_signal

if False:
    from typing import Any, Dict, Optional, Tuple, Union  # noqa: F401

CONFIRMED = const(1)
CANCELLED = const(2)
DEFAULT_CONFIRM = res.load(ui.ICON_CONFIRM)
DEFAULT_CANCEL = res.load(ui.ICON_CANCEL)


class ConfirmDialog(ui.Widget):
    def __init__(
        self,
        content: ui.Widget,
        confirm: Union[str, bytes] = DEFAULT_CONFIRM,
        cancel: Union[str, bytes] = DEFAULT_CANCEL,
        confirm_style: Dict = ui.BTN_CONFIRM,
        cancel_style: Dict = ui.BTN_CANCEL,
    ) -> None:
        self.content = content
        if cancel is not None:
            self.confirm = Button(ui.grid(9, n_x=2), confirm, style=confirm_style)
            self.cancel = Button(ui.grid(8, n_x=2), cancel, style=cancel_style)
        else:
            self.confirm = Button(ui.grid(4, n_x=1), confirm, style=confirm_style)
            self.cancel = None

    def render(self) -> None:
        self.confirm.render()
        if self.cancel is not None:
            self.cancel.render()

    def touch(self, event: int, pos: ui.Pos) -> Any:
        if self.confirm.touch(event, pos) == BTN_CLICKED:
            return CONFIRMED
        if self.cancel is not None:
            if self.cancel.touch(event, pos) == BTN_CLICKED:
                return CANCELLED
        return None

    async def __iter__(self) -> Any:
        if __debug__:
            return await loop.spawn(super().__iter__(), self.content, confirm_signal)
        else:
            return await loop.spawn(super().__iter__(), self.content)


_STARTED = const(-1)
_STOPPED = const(-2)


class HoldToConfirmDialog(ui.Widget):
    def __init__(
        self,
        content: ui.Widget,
        hold: Union[str, bytes] = "Hold to confirm",
        button_style: Dict = ui.BTN_CONFIRM,
        loader_style: Dict = ui.LDR_DEFAULT,
    ) -> None:
        self.content = content
        self.button = Button(ui.grid(4, n_x=1), hold, style=button_style)
        self.loader = Loader(style=loader_style)

        if content.__class__.__iter__ is not Widget.__iter__:
            raise TypeError(
                "HoldToConfirmDialog does not support widgets with custom event loop"
            )

    def taint(self) -> None:
        super().taint()
        self.button.taint()
        self.content.taint()

    def render(self) -> None:
        self.button.render()
        if not self.loader.is_active():
            self.content.render()

    def touch(self, event: int, pos: ui.Pos) -> Any:
        button = self.button
        was_active = button.state == BTN_ACTIVE
        button.touch(event, pos)
        is_active = button.state == BTN_ACTIVE
        if is_active and not was_active:
            ui.display.clear()
            self.loader.start()
            return _STARTED
        if was_active and not is_active:
            self.content.taint()
            if self.loader.stop():
                return CONFIRMED
            else:
                return _STOPPED

    async def __iter__(self) -> Any:
        result = None
        while result is None or result < 0:  # _STARTED or _STOPPED
            if self.loader.is_active():
                if __debug__:
                    result = await loop.spawn(
                        self.loader, super().__iter__(), confirm_signal
                    )
                else:
                    result = await loop.spawn(self.loader, super().__iter__())
            else:
                if __debug__:
                    result = await loop.spawn(super().__iter__(), confirm_signal)
                else:
                    result = await super().__iter__()
        return result
