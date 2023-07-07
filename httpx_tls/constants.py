import h2.settings


class MetaFlags(type):
    def __contains__(cls, x):
        flags = [getattr(cls, flag) for flag in dir(cls) if not flag.startswith('__')]
        return x in flags


class Flags(metaclass=MetaFlags):
    STRICT = 0
    REASONABLE = 1


class DefaultValue:

    def __init__(self, name, on, off, kwarg=False):
        self.name = name
        self.on = on
        self.off = off
        self.kwarg = kwarg

    def get_on(self):
        if not self.kwarg:
            return self.name, self.on
        else:
            return {self.name: self.on}

    def get_off(self):
        if not self.kwarg:
            return self.name, self.off
        else:
            return {self.name: self.off}


class Http2Constants:

    settings_mapping = {1: h2.settings.SettingCodes.HEADER_TABLE_SIZE,
                        2: h2.settings.SettingCodes.ENABLE_PUSH,
                        3: h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS,
                        4: h2.settings.SettingCodes.INITIAL_WINDOW_SIZE,
                        5: h2.settings.SettingCodes.MAX_FRAME_SIZE,
                        6: h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE,
                        8: h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL}

    header_mapping = {'m': b':method',
                      'a': b':authority',
                      's': b':scheme',
                      'p': b':path'}


class TLSExtConstants:
    extension_mapping = {
           0: 'server_name',
           1: 'max_fragment_length',
           2: 'client_certificate_url',
           3: 'trusted_ca_keys',
           4: 'truncated_hmac',
           5: 'status_request',
           6: 'user_mapping',
           7: 'client_authz',
           8: 'server_authz',
           9: 'cert_type',
           10: 'supported_groups',
           11: 'ec_points_format',
           12: 'srp',
           13: 'signature_algorithms',
           14: 'use_srtp',
           15: 'heartbeat',
           16: 'application_layer_protocol_negotiation',
           17: 'status_request_v2',
           18: 'signed_certificate_timestamp',
           19: 'client_certificate_type',
           20: 'server_certificate_type',
           21: 'padding',
           22: 'encrypt_then_mac',
           23: 'extended_master_secret',
           24: 'token_binding',
           25: 'cached_info',
           26: 'tls_lts',
           27: 'certificate_compression',
           28: 'record_size_limit',
           29: 'pwd_protect',
           30: 'pwd_clear',
           31: 'password_salt',
           32: 'ticket_pinning',
           33: 'tls_cert_with_extern_psk',
           34: 'delegated_credential',
           35: 'session_ticket',
           36: 'TLMSP',
           37: 'TLMSP_proxying',
           38: 'TLMSP_delegate',
           39: 'supported_ekt_ciphers',
           41: 'pre_shared_key',
           42: 'early_data',
           43: 'supported_versions',
           44: 'cookie',
           45: 'psk_key_exchange_modes',
           47: 'certificate_authorities',
           48: 'oid_filters',
           49: 'post_handshake_auth',
           50: 'signature_algorithms_cert',
           51: 'key_share',
           52: 'transparency_info',
           53: 'connection_id (depr.)',
           54: 'connection_id',
           55: 'external_id_hash',
           56: 'external_session_id',
           57: 'quic_transport_parameters',
           58: 'ticket_request',
           59: 'dnssec_chain',
           60: 'sequence_number_encryption_algorithms',
           17513: 'application_settings',
           65281: 'renegotiation_info'
    }

    NOT_SUPPORTED = (2, 3, 4, 6, 7, 8, 12, 14, 17, 19, 20, 24, 25, 26, 29,
                     30, 31, 32, 33, 36, 37, 38, 39, 41, 42, 44,
                     47, 48, 50, 52, 53, 54, 55, 56, 57, 58, 59, 60)

    AUTOMATIC = (0, 9, 10, 11, 13, 28, 43, 45, 49, 51,)

    CONFIGURABLE = {5: DefaultValue('use_status_request_ext', on=True, off=False),
                    15: DefaultValue('use_heartbeat_extension', on=True, off=False),
                    16: DefaultValue('alpn', on=[b'http/1.1', b'h2'], off=None, kwarg=True),
                    18: DefaultValue('use_sct_ext', on=True, off=False),
                    21: DefaultValue('usePaddingExtension', on=True, off=False),
                    22: DefaultValue('useEncryptThenMac', on=True, off=False),
                    23: DefaultValue('useExtendedMasterSecret', on=True, off=False),
                    27: DefaultValue('use_certificate_compression', on=True, off=False),
                    34: DefaultValue('use_delegated_credential_ext', on=True, off=False),
                    35: DefaultValue('use_session_ticket_ext', on=True, off=False),
                    17513: DefaultValue('use_alps_ext', on=True, off=False),
                    65281: DefaultValue('use_renegotiation_ext', on=True, off=False)}