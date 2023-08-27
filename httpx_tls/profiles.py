import collections
import copy
from httpx_tls.constants import TLSExtConstants, Http2Constants, TLSVersionConstants
from tlslite import HandshakeSettings, constants
from httpx_tls import database
import struct

ja3_str = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,' \
          '51-23-17513-13-45-65281-5-43-27-11-10-18-35-0-16-21,29-23-24,0'
ja3_str2 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,' \
           '51-23-17513-13-45-65281-5-43-27-11-10-18-35-0-16-21,29-23-24,0'
ja3_str3 = '772,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170' \
           '-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24-25,0'


class Profile:

    @classmethod
    def create_from_useragent(cls, user_agent: str):
        raise NotImplementedError

    @classmethod
    def create_from_version(cls, *args, **kwargs):
        raise NotImplementedError


class TLSProfile(Profile):

    def __init__(self, tls_version=None, ciphers=None, extensions=None, groups=None, settings=None):

        self.ciphers = ciphers if ciphers else []
        self.extensions = extensions if extensions else []
        self.groups = groups if groups else []
        self.tls_version = tls_version if tls_version else (3, 3)
        self.kwargs = {}
        self.settings = settings

        self._create()

    def get_kwargs(self):
        return self.kwargs

    def get_settings(self):
        return self.settings

    @classmethod
    def create_from_ja3(cls, ja3:str):
        ja3 = ja3.strip()
        version, ciphers, extensions, groups, ec_points = ja3.split(',')

        # First, we make sure that all fields are non-empty
        if not all([version, ciphers, extensions, groups, ec_points]):
            raise ValueError("Malformed ja3 string")

        # Then we make sure ec_points is 0. Points compression is obsolete for curves in TLS 1.3 and not exactly
        # supported by tlslite
        if len(ec_points) != 1 or int(ec_points) != 0:
            raise ValueError("only the uncompressed point format (0) is supported for ECPointFormat extension")

        # If all is good, we convert relevant fields into ordered lists of ints
        cipher_order = list(map(int, ciphers.split('-')))
        extension_order = list(map(int, extensions.split('-')))
        groups_order = list(map(int, groups.split('-')))

        # Next we make sure the tls version in the ja3 is valid
        try:
            tls_version = TLSVersionConstants.version_mapping[version]
        except KeyError:
            raise ValueError(f"invalid or unsupported tls version ({version}) provided in the ja3 string")

        return cls(tls_version=tls_version, ciphers=cipher_order, extensions=extension_order, groups=groups_order)

    @classmethod
    def create_from_version(cls, browser: str, version: int, ios_version: int = None):
        browser_data_class: database.Browser = database.get_browser_data_class(browser)
        ja3 = browser_data_class.get_ja3_from_version(version, ios_version=ios_version)
        return cls.create_from_ja3(ja3)

    @classmethod
    def create_from_handshake_settings(cls, settings):
        if not isinstance(settings, HandshakeSettings):
            raise ValueError('')

        return cls(settings=settings)

    @classmethod
    def create_from_useragent(cls, useragent: str):
        device, browser, version, ios_version = database.get_device_and_browser_from_ua(useragent)
        return cls.create_from_version(browser, version, ios_version=ios_version)

    def _create(self):
        # We perform no internal checks if user supplied a settings object themselves
        if self.settings:
            return

        # Make sure extensions, groups and cipher lists only contain unique values
        self.assert_no_duplicates()
        settings = HandshakeSettings()

        # First, we set the minimum tls version we require
        self._set_tls_version(settings)

        # Second, we set all extensions given in self.extensions on the settings object
        self._set_extensions(settings)

        # Then, we set the cipher, group and extension order properties
        self._set_order(settings)

        # We then adjust the key shares based on the order of the groups supplied
        self._adjust_key_shares(settings)

        # Finally, we perform a validation check on the settings object before it is passed deeper down to the
        # handshake functions.
        self.settings = settings.validate()

        # Store this settings object in the profile kwargs as it will be passed to handshake function
        self.kwargs['settings'] = self.settings

    def assert_no_duplicates(self):
        if not self._are_iterable_elements_unique(self.extensions):
            raise ValueError("extensions list must contain only unique values")
        if not self._are_iterable_elements_unique(self.groups):
            raise ValueError("groups list must contain only unique values")
        if not self._are_iterable_elements_unique(self.ciphers):
            raise ValueError("ciphers list must contain only unique values")

    @staticmethod
    def _are_iterable_elements_unique(iterable):
        return len(iterable) - len(set(iterable)) == 0

    def _set_tls_version(self, settings: HandshakeSettings):
        settings.minVersion = self.tls_version

    def _adjust_key_shares(self, settings: HandshakeSettings):
        # Convert default key shares supported by tlslite to their numeric ids
        key_shares = [getattr(constants.GroupName, name) for name in settings.keyShares]

        # Remove key shares if they don't exist in supported groups provided
        key_shares = [ks for ks in key_shares if ks in self.groups]

        # Adjust order of key shares based on the supported groups order
        new_ks = []
        for group in self.groups:
            if group in key_shares:
                new_ks.append(group)

        # If no default key shares are a subset of the supported groups provided, we include the first group in the
        # key shares as a fallback
        if not new_ks:
            new_ks.append(self.groups[0])

        # Get names for numerical ids
        new_ks = [constants.GroupName.toRepr(ks) for ks in new_ks]
        settings.keyShares = new_ks

    def _set_order(self, settings: HandshakeSettings):
        settings.cipher_order = self.ciphers
        settings.groups_order = self.groups
        settings.extension_order = self.extensions

    def _set_extensions(self, settings):

        extensions = self.extensions
        self._check_extensions(extensions)

        # All configurable extensions which the user wants
        configurable_ext = [TLSExtConstants.CONFIGURABLE[ext]
                            for ext in extensions
                            if ext in TLSExtConstants.CONFIGURABLE]

        # A list of 2 length tuples containing the attribute name and corresponding value to set on settings object to
        # enable/disable the configurable extensions
        settings_ext_tuples = []

        # A dictionary representing kwargs that need to be passed to handshake functions to enable specific extensions
        kwarg_ext_dict = {}

        for ext in TLSExtConstants.CONFIGURABLE.values():

            # If the extensions is passed as a kwarg instead of being set on handshake functions, we handle them
            # separately
            if ext.kwarg:
                if ext in configurable_ext:
                    kwarg_ext_dict.update(ext.get_on())
                else:
                    kwarg_ext_dict.update(ext.get_off())

            # If the extensions are set on the settings object, we store the relevant attribute name and value that
            # need to be set
            else:
                if ext in configurable_ext:
                    settings_ext_tuples.append(ext.get_on())
                else:
                    settings_ext_tuples.append(ext.get_off())

        # We set the attributes stored on the settings object
        for name, value in settings_ext_tuples:
            setattr(settings, name, value)

        # We store the kwargs which will later be accessed during handshake
        self.kwargs = kwarg_ext_dict

    @staticmethod
    def _check_extensions(extensions):
        for ext in extensions:
            if ext in TLSExtConstants.AUTOMATIC or ext in TLSExtConstants.CONFIGURABLE:
                continue
            elif ext in TLSExtConstants.NOT_SUPPORTED:
                raise ValueError(f"sending TLS extension '{TLSExtConstants.extension_mapping[ext]}' ({ext}) "
                                 f"is not supported yet")
            else:
                raise ValueError(f"unknown TLS extension ({ext}) supplied")


class Http2Profile(Profile):
    TOTAL_FACTORS = 4

    def __init__(self, h2_settings=None, header_order=None, connection_flow=None, priority_frames=0):
        self.h2_settings = h2_settings
        self.header_order = header_order
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames
        self.validate()
        self._prepare_settings()

    def get_header_order(self):
        if self.header_order:
            return self.header_order.copy()
        else:
            return self.header_order

    def get_settings(self):
        if self.h2_settings:
            return self.h2_settings.copy()
        else:
            return self.h2_settings

    def get_priority_frames(self):
        if self.priority_frames:
            return copy.deepcopy(self.priority_frames)
        else:
            return self.priority_frames

    @classmethod
    def create_from_akamai_str(cls, s: str):
        # Remove all whitespaces from string. Important because some implementations include whitespace right after
        # every comma in header order (m, a, s, p instead of m,a,s,p) which will interfere with our implementation
        # since we compare each header with our stored mapping without whitespace
        s = "".join(s.split())
        s_list = s.split('|')

        if len(s_list) < cls.TOTAL_FACTORS:
            raise ValueError('invalid akamai string (too few values to create a fingerprint)')
        if len(s_list) > cls.TOTAL_FACTORS:
            raise ValueError('invalid akamai string (too many values)')

        settings, connection_flow, priority_frames, header_order = s_list

        # First, we parse the settings
        settings_dict = collections.OrderedDict()
        try:
            # Some implementations erroneously use a comma (',') instead of a semicolon (';') to separate values in
            # SETTINGS frames. We support them in this clause
            if ';' in settings:
                settings = settings.split(';')
            else:
                settings = settings.split(',')

            for pair in settings:
                setting_type, value = map(int, pair.split(':'))
                settings_dict[setting_type] = value
        except ValueError:
            print(s_list)
            raise ValueError("malformed akamai string, cannot parse SETTINGS")

        # Then we parse connection_flow
        try:
            connection_flow = int(connection_flow)
        except ValueError:
            raise ValueError("malformed akamai string, cannot parse value for connection flow (must represent integer)")

        # Now priority frames
        pf = 0
        if priority_frames != '0':
            priority_frames = priority_frames.split(',')
            pf = []
            for frame in priority_frames:
                try:
                    stream, exclusivity, dependency_stream, weight = map(int, frame.split(':'))
                except ValueError:
                    raise ValueError("malformed akamai string, cannot parse priority frames values")

                pf.append({'args': (stream,), 'kwargs': {'exclusive': exclusivity,
                                                         'depends_on': dependency_stream,
                                                         'weight': weight}})

        # Lastly, we parse header order
        header_order = header_order.split(',')
        headers = []
        if len(header_order) != 4:
            raise ValueError(f"malformed akamai string, pseudo-header order contains invalid length of headers (have "
                             f"{len(header_order)}, should be 4)")

        for h in header_order:
            if h not in Http2Constants.header_mapping:
                raise ValueError(f"malformed akamai string, pseudo-header order contains an unknown header denoted by "
                                 f"'{h}'")
            else:
                headers.append(Http2Constants.header_mapping[h])

        return cls(h2_settings=settings_dict, header_order=headers, connection_flow=connection_flow, priority_frames=pf)

    @classmethod
    def create_from_version(cls, device: str, browser: str, version: int, ios_version: int = None):
        browser_data_class: database.Browser = database.get_browser_data_class(browser)
        akamai_str = browser_data_class.get_akamai_str_from_version(version, device, ios_version=ios_version)
        return cls.create_from_akamai_str(akamai_str)

    @classmethod
    def create_from_useragent(cls, useragent: str):
        device, browser, version, ios_version = database.get_device_and_browser_from_ua(useragent)

        return cls.create_from_version(device, browser, version, ios_version=ios_version)

    def validate(self):
        """
        Validate stored fingerprint attributes. Checks performed do not explicitly include length checks to avoid
        repetition since they're already performed in class constructors

        :raise ValueError: If stored attributes are not self-consistent or differ from the specification in
        `Akamai's whitepaper
        <https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>`_
        """

        if self.priority_frames:
            ERROR_MSG = 'invalid frame data in priority_frames, '
            for frame_data in self.priority_frames:
                if 'args' not in frame_data or 'kwargs' not in frame_data:
                    raise ValueError(ERROR_MSG + "must have 'args' and 'kwargs' keys")
                if frame_data['kwargs']['exclusive'] not in (0, 1):
                    raise ValueError(ERROR_MSG + "exclusive bit can only be 0 or 1")
                if frame_data['kwargs']['weight'] < 1 or frame_data['kwargs']['weight'] > 256:
                    raise ValueError(ERROR_MSG + "weight should be between 1 to 256 inclusive")

        if self.connection_flow is not None:
            if self.connection_flow == 0:
                raise ValueError("connection flow cannot be 0 in httpx implementation")
            if self.connection_flow < 0:
                raise ValueError("connection flow cannot be less than 0")

        if self.header_order:
            if set(self.header_order) != set(Http2Constants.header_mapping.values()):
                raise ValueError("invalid header_order, pseudo header_order include ALL headers without any duplicates")

        if self.h2_settings:
            settings_set = set(self.h2_settings)
            if len(settings_set) != len(self.h2_settings):
                raise ValueError("invalid SETTINGS, provided SETTINGS contained duplicate settings identifiers")
            if not settings_set.issubset(Http2Constants.settings_mapping.keys()):
                raise ValueError("invalid SETTINGS, provided SETTINGS contained one or more unknown settings "
                                 "identifiers")

    def _prepare_settings(self):
        new_settings = collections.OrderedDict()
        for key, value in self.h2_settings.items():
            new_settings[Http2Constants.settings_mapping[key]] = value

        self.h2_settings = new_settings









