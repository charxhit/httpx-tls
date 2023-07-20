import sniffio
import anyio
import trio
import httpcore
from ._base import Patch
import ssl
import h2.settings
from collections import OrderedDict
from httpcore._async.http2 import has_body_headers
from httpx_tls.mocks import MockSSLObject


def convert_from_tlslite_generator_to_openssl_output(gen):
    """
    As the name suggests, it iterates over the provided generator and converts the output of tlslite socket's
    to those of openssl (more specifically, the SSLObject).

    :param gen: Generator over a function on tlslite's socket
    :return: Return value of socket function
    """
    try:
        ret = next(gen)
    except StopIteration:
        return
    else:
        # We do not need to consider if ret==1 because in our implementation the tlslite sockets will actually be
        # mock objects with infinite write buffers (so ret == 1 will never be true and SSLWantWriteError will never
        # be raised).
        if ret == 0:
            raise ssl.SSLWantReadError
    return ret


class AsyncSemaphorePatch(Patch):
    patch_for = httpcore._synchronization.AsyncSemaphore

    @staticmethod
    def setup(original_self, original_func) -> None:
        """
        Detect if we're running under 'asyncio' or 'trio' and create
        a semaphore with the correct implementation.
        """
        original_self._backend = sniffio.current_async_library()
        if original_self._backend == "trio":
            import trio

            original_self._trio_semaphore = trio.Semaphore(
                initial_value=1, max_value=original_self._bound
            )
        else:
            import anyio

            original_self._anyio_semaphore = anyio.Semaphore(
                initial_value=1, max_value=original_self._bound
            )

    @staticmethod
    async def acquire(original_self, original_func):
        if not original_self._backend:
            original_self.setup()
            raise ValueError

        return await original_func(original_self)


class AsyncHTTP2ConnectionPatch(Patch):
    patch_for = httpcore._async.http2.AsyncHTTP2Connection

    @staticmethod
    async def _send_request_headers(original_self, original_func, request, stream_id):

        if not request.extensions.get('h2_profile', None):
            return await original_func(original_self, request, stream_id)

        profile = request.extensions['h2_profile']
        header_order = profile.get_header_order()
        connection_flow = profile.connection_flow if profile.connection_flow else 2 ** 24

        end_stream = not has_body_headers(request)

        # In HTTP/2 the ':authority' pseudo-header is used instead of 'Host'.
        # In order to gracefully handle HTTP/1.1 and HTTP/2 we always require
        # HTTP/1.1 style headers, and map them appropriately if we end up on
        # an HTTP/2 connection.
        authority = [v for k, v in request.headers if k.lower() == b"host"][0]
        pseudo_headers = [(b":method", request.method),
                          (b":authority", authority),
                          (b":scheme", request.url.scheme),
                          (b":path", request.url.target)]
        if header_order:
            temp = []
            for header in header_order:
                for ph in pseudo_headers:
                    if header == ph[0]:
                        temp.append(ph)

            if len(temp) != len(pseudo_headers):
                raise ValueError("Incorrect pseudo headers provided for http2 configuration")

            pseudo_headers = temp

        headers = pseudo_headers + [
            (k.lower(), v)
            for k, v in request.headers
            if k.lower() not in (
                b"host",
                b"transfer-encoding",
            )
        ]

        original_self._h2_state.send_headers(stream_id, headers, end_stream=end_stream)
        original_self._h2_state.increment_flow_control_window(connection_flow, stream_id=stream_id)
        await original_self._write_outgoing_data(request)

    @staticmethod
    async def _send_connection_init(original_self, original_func, request):
        if not request.extensions.get('h2_profile', None):
            return await original_func(original_self, request)

        # Get the settings from profile. This will be an ordered dict that preserves the order of insertion. An
        # ordered dict instead of a normal dictionary is used because the preservation of order of insertion became a
        # language specification only in recent python 3.7 version. So, for previous versions, we'll need an ordered
        # dict so that the headers are sent in the same order we were asked to send them in
        profile = request.extensions['h2_profile']
        settings = profile.get_settings()
        connection_flow = profile.connection_flow if profile.connection_flow else 2 ** 24
        max_ts = settings.get(1, 4096)  # Get max table size if provided, else use the rfc default 4096
        priority_frames = profile.get_priority_frames()

        if not settings:
            initial_values = {
                h2.settings.SettingCodes.ENABLE_PUSH: 0,
                # These two are taken from h2 for safe defaults
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100,
                h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 65536,
            }
        else:
            initial_values = settings

        # Even though we'll directly change the settings object later, we still send the initial_values param because
        # h2 does its own validation checks against the values + it actually stores the dictionary values in a deque.
        # Because we don't want our patch to do too much, instead of recreating the logic we leverage the existing
        # one :)
        original_self._h2_state.local_settings = h2.settings.Settings(
            client=True,
            initial_values=initial_values,
        )
        local_settings = original_self._h2_state.local_settings
        if settings:
            # Next, we must enforce strict order of settings frame, and ensure no other frame than the ones we were
            # asked to are sent. To do this, we can directly change the inner settings dictionary, without bothering
            # with the top abstraction layer, to the ordered dict received from the profile.
            inner_settings = local_settings._settings
            new_inner_settings = OrderedDict()
            for key in settings:
                new_inner_settings[key] = inner_settings[key]

            local_settings._settings = new_inner_settings

        # Now, because httpx does not automatically adjust the maximum header table size, we'll do that here. As per the
        # RFC, this should actually be done after we have received an ack, but doing it that way would be unnecessarily
        # *patchy* because, again, httpx does not bother with this at all (plus it's also mostly harmless).
        original_self._h2_state.decoder.max_allowed_table_size = max_ts

        original_self._h2_state.initiate_connection()
        original_self._h2_state.increment_flow_control_window(connection_flow)

        if priority_frames:
            # Lastly, if we are asked to send priority frames, we do so after sending WINDOWS_UPDATE frame
            for frame_data in priority_frames:
                original_self._h2_state.prioritize(*frame_data['args'], **frame_data['kwargs'])

        await original_self._write_outgoing_data(request)

        # if settings:
        #     if h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS not in new_inner_settings:
        #         self._h2_state.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100})
        #         await self._write_outgoing_data(request)
        #         self._h2_state._local_settings_acked()

    @staticmethod
    async def handle_async_request(original_self, original_func, request):
        try:
            return await original_func(original_self, request)
        except ValueError:
            async with original_self._state_lock:
                original_self._request_count -= 1

            return await original_func(original_self, request)


class TrioSSLStreamPatch(Patch):
    patch_for = trio._ssl.SSLStream

    @staticmethod
    async def _retry(original_self, original_func, fn, *args, ignore_want_read=False, is_handshake=False):
        kwargs = {'ignore_want_read': ignore_want_read, 'is_handshake': is_handshake}

        # Check if tlslite is being used. If not, we pass on the function call without any modifications
        if not isinstance(original_self._ssl_object, MockSSLObject):
            return await original_func(original_self, fn, *args, **kwargs)

        # tlslite uses generators to provide async access to underlying sockets, so gen var here will store a
        # generator without actually running the function.
        gen = fn(*args)

        # Instead of passing the raw function to retry, we pass the function
        # convert_from_tlslite_generator_to_openssl_output with the argument as the generator we created above. This
        # is because tlslite uses generators which return (0, 1) instead of SSLWantRead, SSLWantWrite errors like
        # openssl. It follows that if we simply passed the raw function to retry and just translated the (0,
        # 1) output to the corresponding error here and now, then everytime such an error will be raised we will lose
        # the state of the generator. This is not good since handshake functions require multiple read/write calls to
        # the underlying sockets. This is why we have two layers to translate the tlslite outputs-> one to
        # create a generator to receive the output, and one to do the actual translation while preserving the state
        # of the generator it was passed. This second layer is what the trio's retry function has access to.
        return await original_func(original_self, convert_from_tlslite_generator_to_openssl_output, gen, **kwargs)


class AnyioTLSStreamPatch(Patch):
    patch_for = anyio.streams.tls.TLSStream

    @staticmethod
    async def _call_sslobject_method(original_self, original_func, fn, *args):
        # Check if tlslite is being used. If not, we pass on the function call without any modifications
        if not isinstance(original_self._ssl_object, MockSSLObject):
            return await original_func(original_self, fn, *args)

        # tlslite uses generators to provide async access to underlying sockets, so gen var here will store a
        # generator without actually running the function.
        gen = fn(*args)

        return await original_func(original_self, convert_from_tlslite_generator_to_openssl_output, gen)


def patch_async():
    AsyncSemaphorePatch.patch()
    AsyncHTTP2ConnectionPatch.patch()
    TrioSSLStreamPatch.patch()
    AnyioTLSStreamPatch.patch()
