from httpx import AsyncClient, create_ssl_context
from httpx_tls.mocks import SSLContextProxy

__all__ = ["AsyncTLSClient"]


class AsyncTLSClient(AsyncClient):

    def __init__(self, tls_config=None, h2_config=None, verify=True, cert=None, trust_env=True, **kwargs):

        context = create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        verify = SSLContextProxy(context, tls_config)
        self.h2_config = h2_config

        super().__init__(verify=verify, cert=cert, trust_env=trust_env, **kwargs)

    def build_request(self, *args, **kwargs):
        request = super().build_request(*args, **kwargs)
        request.extensions['h2_profile'] = self.h2_config
        return request




