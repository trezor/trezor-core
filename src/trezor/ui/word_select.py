from micropython import const

from trezor import loop, ui
from trezor.ui import Widget
from trezor.ui.button import BTN_CLICKED, Button

if __debug__:
    from apps.debug import input_signal


_W12 = const(12)
_W18 = const(18)
_W20 = const(20)
_W24 = const(24)
_W33 = const(33)


class WordSelector(Widget):
    def __init__(self, content):
        self.content = content
        self.buttons = {
            _W12: Button(ui.grid(6, n_y=4), str(_W12), style=ui.BTN_KEY),
            _W18: Button(ui.grid(7, n_y=4), str(_W18), style=ui.BTN_KEY),
            _W20: Button(ui.grid(8, n_y=4), str(_W20), style=ui.BTN_KEY),
            _W24: Button(ui.grid(9, n_y=4), str(_W24), style=ui.BTN_KEY),
            _W33: Button(ui.grid(10, n_y=4), str(_W33), style=ui.BTN_KEY),
        }

    def taint(self):
        super().taint()
        for b in self.buttons.values():
            b.taint()

    def render(self):
        for b in self.buttons.values():
            b.render()

    def touch(self, event, pos):
        for key, button in self.buttons.items():
            if button.touch(event, pos) == BTN_CLICKED:
                return key

    async def __iter__(self):
        if __debug__:
            result = await loop.spawn(super().__iter__(), self.content, input_signal)
            if isinstance(result, str):
                return int(result)
            else:
                return result
        else:
            return await loop.spawn(super().__iter__(), self.content)
