from httpx import AsyncClient, create_ssl_context
from httpx_tls.mocks import SSLContextProxy

__all__ = ["AsyncTLSClient"]


class AsyncTLSClient(AsyncClient):

    def __init__(self, tls_config=None, h2_config=None, verify=True, cert=None, trust_env=True,
                 randomize_tls_extensions=True, **kwargs):

        # If randomize_tls_extensions is enabled and tls_config is a TLSProfile, set the flag
        if randomize_tls_extensions and tls_config is not None:
            if hasattr(tls_config, 'randomize_extensions'):
                tls_config.randomize_extensions = randomize_tls_extensions

        context = create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        verify = SSLContextProxy(context, tls_config)
        self.h2_config = h2_config

        super().__init__(verify=verify, cert=cert, trust_env=trust_env, **kwargs)

    def build_request(self, *args, **kwargs):
        request = super().build_request(*args, **kwargs)
        request.extensions['h2_profile'] = self.h2_config
        return request

