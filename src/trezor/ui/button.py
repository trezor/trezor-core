from micropython import const

from trezor import io, ui
from trezor.ui import contains, display, rotate

if False:
    from typing import Dict, Optional, Tuple, Union  # noqa: F401

# button events
BTN_CLICKED = const(1)

# button states
BTN_INITIAL = const(0)
BTN_DISABLED = const(1)
BTN_FOCUSED = const(2)
BTN_ACTIVE = const(3)

# constants
ICON = const(16)  # icon size in pixels
BORDER = const(4)  # border size in pixels


class Button(ui.Widget):
    def __init__(
        self, area: ui.Area, content: Union[str, bytes], style: Dict = ui.BTN_KEY
    ) -> None:
        self.area = area
        self.content = content
        self.normal_style = style["normal"] or ui.BTN_KEY["normal"]
        self.active_style = style["active"] or ui.BTN_KEY["active"]
        self.disabled_style = style["disabled"] or ui.BTN_KEY["disabled"]
        self.state = BTN_INITIAL

    def enable(self) -> None:
        if self.state == BTN_DISABLED:
            self.state = BTN_INITIAL
            self.tainted = True

    def disable(self) -> None:
        if self.state != BTN_DISABLED:
            self.state = BTN_DISABLED
            self.tainted = True

    def render(self) -> None:
        if not self.tainted:
            return
        state = self.state
        if state == BTN_DISABLED:
            s = self.disabled_style
        elif state == BTN_ACTIVE:
            s = self.active_style
        else:
            s = self.normal_style
        ax, ay, aw, ah = self.area
        self.render_background(s, ax, ay, aw, ah)
        self.render_content(s, ax, ay, aw, ah)
        self.tainted = False

    def render_background(
        self, s: Dict[str, int], ax: int, ay: int, aw: int, ah: int
    ) -> None:
        radius = s["radius"]
        bg_color = s["bg-color"]
        border_color = s["border-color"]
        if border_color != bg_color:
            # render border and background on top of it
            display.bar_radius(ax, ay, aw, ah, border_color, ui.BG, radius)
            display.bar_radius(
                ax + BORDER,
                ay + BORDER,
                aw - BORDER * 2,
                ah - BORDER * 2,
                bg_color,
                border_color,
                radius,
            )
        else:
            # render only the background
            display.bar_radius(ax, ay, aw, ah, bg_color, ui.BG, radius)

    def render_content(
        self, s: Dict[str, int], ax: int, ay: int, aw: int, ah: int
    ) -> None:
        c = self.content
        tx = ax + aw // 2
        ty = ay + ah // 2 + 8
        if isinstance(c, str):
            display.text_center(
                tx, ty, c, s["text-style"], s["fg-color"], s["bg-color"]
            )
        else:
            display.icon(tx - ICON // 2, ty - ICON, c, s["fg-color"], s["bg-color"])

    def touch(self, event: int, pos: ui.Pos) -> Optional[int]:
        pos = rotate(pos)

        state = self.state
        if state == BTN_DISABLED:
            return None

        if event == io.TOUCH_START:
            if contains(self.area, pos):
                self.state = BTN_ACTIVE
                self.tainted = True

        elif event == io.TOUCH_MOVE:
            if contains(self.area, pos):
                if state == BTN_FOCUSED:
                    self.state = BTN_ACTIVE
                    self.tainted = True
            else:
                if state == BTN_ACTIVE:
                    self.state = BTN_FOCUSED
                    self.tainted = True

        elif event == io.TOUCH_END:
            if state != BTN_INITIAL:
                self.state = BTN_INITIAL
                self.tainted = True
                if state == BTN_ACTIVE and contains(self.area, pos):
                    return BTN_CLICKED

        return None
