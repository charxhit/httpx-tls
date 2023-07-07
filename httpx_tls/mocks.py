from tlslite import TLSConnection
from ssl import SSLError, SSLContext
import errno
import time
import socket


class SSLContextProxy:
    __class__ = SSLContext
    writable = {
        "_context",
        "_http_config",
        "_alpn_protocols",
        "_client_cert"
    }

    def __init__(self, context: SSLContext, http_config):
        self._context = context
        self._http_config = http_config
        self._alpn_protocols = None
        self._client_cert = (None, None)  # certificate, keyfile

    def get_alpn_protocols(self):
        return self._alpn_protocols

    def get_profile(self):
        return self._http_config

    def get_cert(self):
        return self._client_cert

    def __getattr__(self, item):
        return getattr(self._context, item)

    def __setattr__(self, key, value):
        if key in self.writable:
            return super().__setattr__(key, value)

        return setattr(self._context, key, value)

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None):
        """
        Intercept call to wrap_bio and return a mocked SSLObject instead.

        :return: MockSSLObject
        """
        return MockSSLObject(self, server_side, server_hostname, incoming, outgoing)

    def load_verify_locations(self, *args, **kwargs):
        """
        Intercept and ignore call to load CA trusted certificates since tlslite does
        not perform certificate verification anyway

        :return: None
        """

        return

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        """
        Intercept call to load client certificate and store the details provided to be passed during handshake

        :param str certfile: Path to client certificate chain to be passed during verification, if any
        :param str keyfile: Path to keyfile storing private key for the certificate. If None, certfile
                            itself must have the private key.
        :param NoneType password: Must be None, passing any other value is not supported.
        :return None
        """

        if password is not None:
            raise ValueError("loading encrypted client certificates is not supported")

        if keyfile:
            self._client_cert = (certfile, keyfile)
        else:
            self._client_cert = (certfile, certfile)

    def set_alpn_protocols(self, protocols):
        """
        Intercept call to setter and store the ALPN protocols client should advertise during handshake

        :param list protocols: An iterable of strings specifying protocols to advertise
                               support for in order of preference.
        :return: None
        """

        assert len(protocols) != 0, "ALPN protocols cannot be an empty iterable"
        self._alpn_protocols = protocols


class MockOpenSSLMemBIO:

    def __init__(self):
        self._pipe = bytearray()
        self._eof = False

    @property
    def pending(self):
        return len(self._pipe)

    @property
    def eof(self):
        return self._eof is True and len(self._pipe) == 0

    def write_eof(self):
        self._eof = True

    def read(self, n=-1):
        if n < 0:
            n = len(self._pipe)
        ret = self._pipe[:n]
        self._pipe = self._pipe[n:]
        return ret

    def write(self, buf):
        if self.eof:
            raise SSLError('cannot write() after write_eof()')

        self._pipe += buf
        return len(buf)


class MockTLSSocket:

    def __init__(self, incoming: MockOpenSSLMemBIO, outgoing: MockOpenSSLMemBIO):
        self._incoming = incoming
        self._outgoing = outgoing
        self._closed = False

    def send(self, data):
        self._check_closed()
        return self._outgoing.write(data)

    def sendall(self, data):
        return self.send(data)

    def recv(self, bufsize):
        self._check_closed()

        if self._incoming.pending == 0:
            raise socket.error(errno.EWOULDBLOCK)
        return self._incoming.read(bufsize)

    def _check_closed(self):
        if self._closed:
            raise OSError("OSError: [WinError 10038] An operation was attempted on something that is not a socket")

    def close(self):
        self._closed = True

    def shutdown(self):
        raise NotImplementedError


class MockSSLSession:

    def __init__(self):
        self.timeout = 7200
        self.time = time.time()
        self.id = b''


class MockSSLObject:
    """This is where we add methods like do_handshake and shit for tlsConnection"""

    def __init__(self, context, server_side, server_hostname, incoming, outgoing):
        sock = MockTLSSocket(incoming, outgoing)
        self._outgoing = outgoing
        self.context = context
        self.server_side = server_side
        self.server_hostname = server_hostname
        self.tls_connection = TLSConnection(sock)

    def _prepare_alpn_protocol(self, alpn_protocols):
        in_bytes = []
        if not alpn_protocols:
            return
        for protocol in alpn_protocols:
            b = bytes(protocol, 'ascii')
            in_bytes.append(b)

        return in_bytes

    def get_channel_binding(self):
        raise NotImplementedError

    def get_peercert(self, *args):
        raise NotImplementedError

    @property
    def selected_npn_protocol(self):
        return self.tls_connection.next_proto

    @property
    def session_reused(self):
        return self.tls_connection.resumed

    @property
    def cipher(self):
        # return self.tls_connection.session.cipherSuite
        return None

    @property
    def shared_ciphers(self):
        # return self.cipher
        return None

    def version(self):
        return self.tls_connection.getVersionName()

    def pending(self):
        return self._outgoing.pending

    def selected_alpn_protocol(self):
        alpn = self.tls_connection.session.appProto
        return alpn.decode() if alpn is not None else alpn

    def read(self, max_bytes):
        for result in self.tls_connection.readAsync(max=max_bytes):

            yield result

    def write(self, buf):
        for result in self.tls_connection.writeAsync(buf):
            yield result

    def do_handshake(self):
        kwargs = self._get_kwargs()
        for result in self.tls_connection.handshakeClientCert(async_=True, **kwargs):
            yield result

    def unwrap(self):
        self.tls_connection = None

    def _get_kwargs(self):
        kwargs = {}
        profile = self.context.get_profile()
        alpn = self.context.get_alpn_protocols()
        alpn = self._prepare_alpn_protocol(alpn)
        cert = self.context.get_cert()

        # To initialize SNI ext
        if self.server_hostname:
            kwargs['serverName'] = self.server_hostname

        # Change alpn from placeholder value (in profile kwargs) to actual value
        if alpn:
            kwargs['alpn'] = alpn

        # If client certificate provided, inform tlslite by passing in as kwarg
        if all(cert):
            kwargs['certChain'] = cert[0]
            kwargs['privateKey'] = cert[1]

        # If no profile was passed, then simply above kwargs are required
        if not profile:
            return kwargs

        # Mutate profile kwargs with the ones ascertained here and return their union (kwargs passed through httpx
        # take preference if kwarg present at both places)
        kwargs_profile = profile.get_kwargs()
        kwargs_profile.update(kwargs)
        return kwargs_profile




