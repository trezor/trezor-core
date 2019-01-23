from trezor import loop

if False:
    from typing import Coroutine, List, Optional, Callable  # noqa: F401

workflows = []  # type: List[Coroutine]
layouts = []  # type: List[Coroutine]
default = None  # type: Optional[Coroutine]
default_layout = None  # type: Optional[Callable[[], Coroutine]]


def onstart(w: Coroutine) -> None:
    workflows.append(w)


def onclose(w: Coroutine) -> None:
    workflows.remove(w)
    if not layouts and default_layout is not None:
        startdefault(default_layout)


def closedefault() -> None:
    global default

    if default:
        loop.close(default)
        default = None


def startdefault(layout: Callable[[], Coroutine]) -> None:
    global default
    global default_layout

    if not default:
        default_layout = layout
        default = layout()
        loop.schedule(default)


def restartdefault() -> None:
    global default_layout
    d = default_layout
    closedefault()
    if d is not None:
        startdefault(d)


def onlayoutstart(l: Coroutine) -> None:
    closedefault()
    layouts.append(l)


def onlayoutclose(l: Coroutine) -> None:
    if l in layouts:
        layouts.remove(l)
