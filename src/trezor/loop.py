"""
Implements an event loop with cooperative multitasking and async I/O.  Tasks in
the form of python coroutines (either plain generators or `async` functions) are
stepped through until completion, and can get asynchronously blocked by
`yield`ing or `await`ing a syscall.

See `schedule`, `run`, and syscalls `sleep`, `wait`, `signal` and `spawn`.
"""

import utime
import utimeq
from micropython import const

from trezor import io, log

if False:
    from typing import (  # noqa: F401
        Any,
        Awaitable,
        Callable,
        Coroutine,
        Dict,
        Generator,
        List,
        Optional,
        Set,
    )

# function to call after every task step
after_step_hook = None  # type: Optional[Callable[[], None]]

# tasks scheduled for execution in the future
_queue = utimeq.utimeq(64)

# tasks paused on I/O
_paused = {}  # type: Dict[int, Set[Coroutine]]

if __debug__:
    # for performance stats
    import array

    log_delay_pos = 0
    log_delay_rb_len = const(10)
    log_delay_rb = array.array("i", [0] * log_delay_rb_len)


def schedule(task: Coroutine, value: Any = None, deadline: int = None) -> None:
    """
    Schedule task to be executed with `value` on given `deadline` (in
    microseconds).  Does not start the event loop itself, see `run`.
    """
    if deadline is None:
        deadline = utime.ticks_us()
    _queue.push(deadline, task, value)


def pause(task: Coroutine, iface: int) -> None:
    tasks = _paused.get(iface, None)
    if tasks is None:
        tasks = _paused[iface] = set()
    tasks.add(task)


def close(task: Coroutine) -> None:
    for iface in _paused:
        _paused[iface].discard(task)
    _queue.discard(task)
    task.close()


def run() -> None:
    """
    Loop forever, stepping through scheduled tasks and awaiting I/O events
    inbetween.  Use `schedule` first to add a coroutine to the task queue.
    Tasks yield back to the scheduler on any I/O, usually by calling `await` on
    a `Syscall`.
    """

    if __debug__:
        global log_delay_pos

    max_delay = const(1000000)  # usec delay if queue is empty

    task_entry = [0, 0, 0]  # deadline, task, value
    msg_entry = [0, 0]  # iface | flags, value
    while _queue or _paused:
        # compute the maximum amount of time we can wait for a message
        if _queue:
            delay = utime.ticks_diff(_queue.peektime(), utime.ticks_us())
        else:
            delay = max_delay

        if __debug__:
            # add current delay to ring buffer for performance stats
            log_delay_rb[log_delay_pos] = delay
            log_delay_pos = (log_delay_pos + 1) % log_delay_rb_len

        if io.poll(_paused, msg_entry, delay):
            # message received, run tasks paused on the interface
            msg_tasks = _paused.pop(msg_entry[0], ())
            for task in msg_tasks:
                _step(task, msg_entry[1])
        else:
            # timeout occurred, run the first scheduled task
            if _queue:
                _queue.pop(task_entry)
                _step(task_entry[1], task_entry[2])  # type: ignore
                # error: Argument 1 to "_step" has incompatible type "int"; expected "Coroutine[Any, Any, Any]"
                # rationale: We use untyped lists here, because that is what the C API supports.


def _step(task: Coroutine, value: Any) -> None:
    try:
        if isinstance(value, Exception):
            result = task.throw(value)  # type: ignore
            # error: Argument 1 to "throw" of "Coroutine" has incompatible type "Exception"; expected "Type[BaseException]"
            # rationale: In micropython, generator.throw() accepts directly the exception object.
        else:
            result = task.send(value)
    except StopIteration:  # as e:
        if __debug__:
            log.debug(__name__, "finish: %s", task)
    except Exception as e:
        if __debug__:
            log.exception(__name__, e)
    else:
        if isinstance(result, Syscall):
            result.handle(task)
        elif result is None:
            schedule(task)
        else:
            if __debug__:
                log.error(__name__, "unknown syscall: %s", result)
        if after_step_hook:
            after_step_hook()


class Syscall:
    """
    When tasks want to perform any I/O, or do any sort of communication with the
    scheduler, they do so through instances of a class derived from `Syscall`.
    """

    def __iter__(self) -> Coroutine:  # type: ignore
        # support `yield from` or `await` on syscalls
        return (yield self)

    def __await__(self) -> Generator:
        return self.__iter__()  # type: ignore

    def handle(self, task: Coroutine) -> None:
        pass


class sleep(Syscall):
    """
    Pause current task and resume it after given delay.  Although the delay is
    given in microseconds, sub-millisecond precision is not guaranteed.  Result
    value is the calculated deadline.

    Example:

    >>> planned = await loop.sleep(1000 * 1000)  # sleep for 1ms
    >>> print('missed by %d us', utime.ticks_diff(utime.ticks_us(), planned))
    """

    def __init__(self, delay_us: int) -> None:
        self.delay_us = delay_us

    def handle(self, task: Coroutine) -> None:
        deadline = utime.ticks_add(utime.ticks_us(), self.delay_us)
        schedule(task, deadline, deadline)


class wait(Syscall):
    """
    Pause current task, and resume only after a message on `msg_iface` is
    received.  Messages are received either from an USB interface, or the
    touch display.  Result value a tuple of message values.

    Example:

    >>> hid_report, = await loop.wait(0xABCD)  # await USB HID report
    >>> event, x, y = await loop.wait(io.TOUCH)  # await touch event
    """

    def __init__(self, msg_iface: int) -> None:
        self.msg_iface = msg_iface

    def handle(self, task: Coroutine) -> None:
        pause(task, self.msg_iface)


_NO_VALUE = object()


class signal(Syscall):
    """
    Pause current task, and let other running task to resume it later with a
    result value or an exception.

    Example:

    >>> # in task #1:
    >>> signal = loop.signal()
    >>> result = await signal
    >>> print('awaited result:', result)
    >>> # in task #2:
    >>> signal.send('hello from task #2')
    >>> # prints in the next iteration of the event loop
    """

    def __init__(self) -> None:
        self.value = _NO_VALUE
        self.task = None  # type: Optional[Coroutine]

    def handle(self, task: Coroutine) -> None:
        self.task = task
        self._deliver()

    def send(self, value: Any) -> None:
        self.value = value
        self._deliver()

    def _deliver(self) -> None:
        if self.task is not None and self.value is not _NO_VALUE:
            schedule(self.task, self.value)
            self.task = None
            self.value = _NO_VALUE

    def __iter__(self) -> Coroutine:  # type: ignore
        try:
            return (yield self)
        except:  # noqa: E722
            self.task = None
            raise


class spawn(Syscall):
    """
    Execute one or more children tasks and wait until one of them exits.
    Return value of `spawn` is the return value of task that triggered the
    completion.  By default, `spawn` returns after the first child completes, and
    other running children are killed (by cancelling any pending schedules and
    calling `close()`).

    Example:

    >>> # async def wait_for_touch(): ...
    >>> # async def animate_logo(): ...
    >>> touch_task = wait_for_touch()
    >>> animation_task = animate_logo()
    >>> waiter = loop.spawn(touch_task, animation_task)
    >>> result = await waiter
    >>> if animation_task in waiter.finished:
    >>>     print('animation task returned', result)
    >>> else:
    >>>     print('touch task returned', result)

    Note: You should not directly `yield` a `spawn` instance, see logic in
    `spawn.__iter__` for explanation.  Always use `await`.
    """

    def __init__(self, *children: Awaitable, exit_others: bool = True) -> None:
        self.children = children
        self.exit_others = exit_others

    def handle(self, task: Coroutine) -> None:
        self.callback = task
        self.finished = []  # type: List[Awaitable]  # children that finished
        self.scheduled = []  # type: List[Coroutine]  # scheduled wrapper tasks
        for index, child in enumerate(self.children):
            parent = self._wait(child, index)
            schedule(parent)
            self.scheduled.append(parent)

    def exit(self, skip_index: int = -1) -> None:
        for index, parent in enumerate(self.scheduled):
            if index != skip_index:
                close(parent)

    async def _wait(self, child: Awaitable, index: int) -> None:
        try:
            result = await child
        except Exception as e:
            self._finish(child, index, e)
            if __debug__:
                log.exception(__name__, e)
        else:
            self._finish(child, index, result)

    def _finish(self, child: Awaitable, index: int, result: Any) -> None:
        if not self.finished:
            self.finished.append(child)
            if self.exit_others:
                self.exit(index)
            schedule(self.callback, result)

    def __iter__(self) -> Coroutine:  # type: ignore
        try:
            return (yield self)
        except:  # noqa: E722
            # exception was raised on the waiting task externally with
            # close() or throw(), kill the children tasks and re-raise
            self.exit()
            raise
