import protobuf
from trezor import log, loop, messages, utils, workflow
from trezor.messages.Failure import Failure
from trezor.wire import codec_v1
from trezor.wire.errors import *

from apps.common import seed

_workflow_handlers = {}


def add(mtype, pkgname, modname, namespace=None):
    """Shortcut for registering a dynamically-imported Protobuf workflow."""
    if namespace is not None:
        register(mtype, keychain_workflow, namespace, import_workflow, pkgname, modname)
    else:
        register(mtype, import_workflow, pkgname, modname)


def register(mtype, handler, *args):
    """Register `handler` to get scheduled after `mtype` message is received."""
    if isinstance(mtype, type) and issubclass(mtype, protobuf.MessageType):
        mtype = mtype.MESSAGE_WIRE_TYPE
    if mtype in _workflow_handlers:
        raise KeyError
    _workflow_handlers[mtype] = (handler, args)


def setup(iface):
    """Initialize the wire stack on passed USB interface."""
    loop.schedule(session_handler(iface, codec_v1.SESSION_ID))


class Context:
    def __init__(self, iface, sid):
        self.iface = iface
        self.sid = sid

    async def call(self, msg, *types):
        """
        Reply with `msg` and wait for one of `types`. See `self.write()` and
        `self.read()`.
        """
        await self.write(msg)
        del msg
        return await self.read(types)

    async def read(self, types):
        """
        Wait for incoming message on this wire context and return it.  Raises
        `UnexpectedMessageError` if the message type does not match one of
        `types`; and caller should always make sure to re-raise it.
        """
        if __debug__:
            log.debug(
                __name__, "%s:%x read: %s", self.iface.iface_num(), self.sid, types
            )

        msg = await codec_v1.read_message(self.iface, _message_buffer)

        # if we got a message with unexpected type, raise the message via
        # `UnexpectedMessageError` and let the session handler deal with it
        if msg.type not in types:
            raise UnexpectedMessageError(msg)

        # look up the protobuf class and parse the message
        pbtype = messages.get_type(msg.type)

        return protobuf.load_message(msg, pbtype)

    async def write(self, msg):
        """
        Write a protobuf message to this wire context.
        """
        writer = self.getwriter()

        if __debug__:
            log.debug(
                __name__, "%s:%x write: %s", self.iface.iface_num(), self.sid, msg
            )

        # get the message size
        fields = msg.get_fields()
        size = protobuf.count_message(msg, fields)

        # write the message
        writer.setheader(msg.MESSAGE_WIRE_TYPE, size)
        protobuf.dump_message(writer, msg, fields)
        await writer.aclose()

    def wait(self, *tasks):
        """
        Wait until one of the passed tasks finishes, and return the result,
        while servicing the wire context.  If a message comes until one of the
        tasks ends, `UnexpectedMessageError` is raised.
        """
        return loop.spawn(self.read(()), *tasks)


class UnexpectedMessageError(Exception):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg


async def session_handler(iface, sid):
    msg = None
    ctx = Context(iface, sid)
    while True:
        try:
            # wait for new message, if needed, and find handler for it
            if msg is None:
                msg = await ctx.read()

            # if the message type is unknown, respond with an unknown message error
            if msg.type not in _workflow_handlers:
                code = FailureType.UnexpectedMessage
                response = Failure(code=code, message="Unexpected message")
                await ctx.write(response)
                continue

            # create the workflow handler, parse the message as protobuf
            handler, args = _workflow_handlers[msg.type]
            modules = utils.unimport_begin()
            request = protobuf.load_message(msg, messages.get_type(msg.type))
            workflow_handler = handler(ctx, request, *args)
            try:
                workflow.onstart(workflow_handler)
                try:
                    response = await workflow_handler

                except Error as exc:
                    if __debug__:
                        log.warning(__name__, exc)
                    # respond with specific error code and message
                    response = Failure(code=exc.code, message=exc.message)

                except Exception:
                    if __debug__:
                        log.exception(__name__, exc)
                    # respond with a generic error
                    code = FailureType.FirmwareError
                    response = Failure(code=code, message="Firmware error")

                # send the response returned by the workflow
                if response is not None:
                    await ctx.write(response)
            finally:
                workflow.onclose(workflow_handler)
                utils.unimport_end(modules)

        except Exception as exc:
            if __debug__:
                log.exception(__name__, exc)

        # read new message in next iteration
        msg = None


async def keychain_workflow(ctx, req, namespace, handler, *args):
    keychain = await seed.get_keychain(ctx, namespace)
    args += (keychain,)
    try:
        return await handler(ctx, req, *args)
    finally:
        keychain.__del__()


def import_workflow(ctx, req, pkgname, modname, *args):
    modpath = "%s.%s" % (pkgname, modname)
    module = __import__(modpath, None, None, (modname,), 0)
    handler = getattr(module, modname)
    return handler(ctx, req, *args)


async def _handle_unexpected_message(ctx, msg):

    await ctx.write(
        Failure(code=FailureType.UnexpectedMessage, message="Unexpected message")
    )
