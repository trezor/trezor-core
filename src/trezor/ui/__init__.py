import math
import utime
from micropython import const
from trezorui import Display

from trezor import io, loop, res, utils, workflow

if False:
    from typing import Any, Callable, Generator, Iterator, Optional, Tuple  # noqa: F401

    Pos = Tuple[int, int]
    Area = Tuple[int, int, int, int]

display = Display()

# in debug mode, display an indicator in top right corner
if __debug__:

    def debug_display_refresh() -> None:
        display.bar(Display.WIDTH - 8, 0, 8, 8, 0xF800)
        display.refresh()

    loop.after_step_hook = debug_display_refresh

# in both debug and production, emulator needs to draw the screen explicitly
elif utils.EMULATOR:
    loop.after_step_hook = display.refresh

# re-export constants from modtrezorui
NORMAL = Display.FONT_NORMAL
BOLD = Display.FONT_BOLD
MONO = Display.FONT_MONO
SIZE = Display.FONT_SIZE
WIDTH = Display.WIDTH
HEIGHT = Display.HEIGHT


def lerpi(a: int, b: int, t: float) -> int:
    return int(a + t * (b - a))


def rgb(r: int, g: int, b: int) -> int:
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3)


def blend(ca: int, cb: int, t: float) -> int:
    return rgb(
        lerpi((ca >> 8) & 0xF8, (cb >> 8) & 0xF8, t),
        lerpi((ca >> 3) & 0xFC, (cb >> 3) & 0xFC, t),
        lerpi((ca << 3) & 0xF8, (cb << 3) & 0xF8, t),
    )


# import style definitions
from trezor.ui.style import *  # isort:skip


def contains(area: Area, pos: Pos) -> bool:
    x, y = pos
    ax, ay, aw, ah = area
    return ax <= x <= ax + aw and ay <= y <= ay + ah


def rotate(pos: Pos) -> Pos:
    r = display.orientation()
    if r == 0:
        return pos
    x, y = pos
    if r == 90:
        return (y, WIDTH - x)
    if r == 180:
        return (WIDTH - x, HEIGHT - y)
    if r == 270:
        return (HEIGHT - y, x)
    raise ValueError()


def pulse(delay: int) -> Iterator[float]:
    while True:
        # normalize sin from interval -1:1 to 0:1
        yield 0.5 + 0.5 * math.sin(utime.ticks_us() / delay)


async def alert(count: int = 3) -> None:
    short_sleep = loop.sleep(20000)
    long_sleep = loop.sleep(80000)
    current = display.backlight()
    for i in range(count * 2):
        if i % 2 == 0:
            display.backlight(BACKLIGHT_MAX)
            await short_sleep
        else:
            display.backlight(BACKLIGHT_NORMAL)
            await long_sleep
    display.backlight(current)


async def click() -> Pos:
    touch = loop.wait(io.TOUCH)
    while True:
        ev, *pos = await touch  # type: int, Pos
        if ev == io.TOUCH_START:
            break
    while True:
        ev, *pos = await touch
        if ev == io.TOUCH_END:
            break
    return pos


def backlight_slide(
    val: int, delay: int = 35000, step: int = 20
) -> Coroutine:  # type: ignore
    sleep = loop.sleep(delay)
    current = display.backlight()
    for i in range(current, val, -step if current > val else step):
        display.backlight(i)
        yield sleep


def layout(f: Callable) -> Callable:
    async def inner(*args: Any, **kwargs: Any) -> Any:
        await backlight_slide(BACKLIGHT_DIM)
        slide = backlight_slide(BACKLIGHT_NORMAL)
        try:
            layout = f(*args, **kwargs)
            workflow.onlayoutstart(layout)
            loop.schedule(slide)
            display.clear()
            return await layout
        finally:
            loop.close(slide)
            workflow.onlayoutclose(layout)

    return inner


def header(
    title: str, icon: str = ICON_DEFAULT, fg: int = FG, bg: int = BG, ifg: int = GREEN
) -> None:
    if icon is not None:
        display.icon(14, 15, res.load(icon), ifg, bg)
    display.text(44, 35, title, BOLD, fg, bg)


VIEWX = const(6)
VIEWY = const(9)


def grid(
    i: int,
    n_x: int = 3,
    n_y: int = 5,
    start_x: int = VIEWX,
    start_y: int = VIEWY,
    end_x: int = (WIDTH - VIEWX),
    end_y: int = (HEIGHT - VIEWY),
    cells_x: int = 1,
    cells_y: int = 1,
    spacing: int = 0,
) -> Area:
    w = (end_x - start_x) // n_x
    h = (end_y - start_y) // n_y
    x = (i % n_x) * w
    y = (i // n_x) * h
    return (x + start_x, y + start_y, (w - spacing) * cells_x, (h - spacing) * cells_y)


class Widget:
    tainted = True

    def taint(self) -> None:
        self.tainted = True

    def render(self) -> None:
        pass

    def touch(self, event: int, pos: Pos) -> Any:
        pass

    def __iter__(self) -> Coroutine:  # type: ignore
        touch = loop.wait(io.TOUCH)
        result = None
        while result is None:
            self.render()
            event, *pos = yield touch  # type: int, Pos
            result = self.touch(event, pos)
        return result

    def __await__(self) -> Generator:
        return self.__iter__()  # type: ignore
