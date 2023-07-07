import re
import user_agents
from .constants import Flags


class Http2Data:
    akamai_versions = {}


class ChromiumDesktop(Http2Data):
    akamai_versions = {
        '106-114': '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '80-105': '1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '73-79': '1:65536,3:1000,4:6291456|15663105|0|m,a,s,p',
    }


class ChromiumMobile(ChromiumDesktop):
    pass


class FirefoxDesktop(Http2Data):
    akamai_versions = {
        '65-113': "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
    }


class FirefoxMobile(Http2Data):
    akamai_versions = {
        '65-113': "1:4096,4:32768,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
    }


class SafariDesktop(Http2Data):
    akamai_versions = {
        '14-16': "4:4194304,3:100|10485760|0|m,s,p,a",
        '13': "4:1048576,3:100|10485760|0|m,s,p,a",
    }


class SafariMobile(Http2Data):
    akamai_versions = {
        '14-16': "4:2097152,3:100|10485760|0|m,s,p,a",
        '13': "4:1048576,3:100|10485760|0|m,s,p,a",
    }


class Browser:
    ja3_versions = {}
    h2_mapping = {
        'desktop': None,
        'android': None,
        'ios': None
                  }
    name = None
    chromium = False
    chromium_pattern = re.compile(r' Chrome/(.+?)(?: |$)')
    reasonable = 10

    @classmethod
    def get_ja3_from_version(cls, version: int, ios_version: int = None, flag=Flags.REASONABLE):
        cls.assert_flags_ok(flag)

        version_dict = cls.ja3_versions
        if ios_version:
            cls.assert_ios_version_correct('ios', ios_version)
            version_dict = Safari.ja3_versions
            version = ios_version

        ja3_str = cls._find_version_from_given_dict(version, version_dict, flag=flag)
        if not ja3_str:
            if ios_version:
                error_with_version = f"{cls.name} on iOS version {ios_version}"
            elif cls.chromium:
                error_with_version = f"{cls.name} based on chromium version {version}"
            else:
                error_with_version = f"{cls.name} version {version}"

            raise ValueError(f"no matching ja3 string found in database for " + error_with_version)

        return ja3_str

    @classmethod
    def get_akamai_str_from_version(cls, version: int, device: str, ios_version: int = None,
                                    flag: int = Flags.REASONABLE):

        cls.assert_flags_ok(flag)
        cls.assert_ios_version_correct(device, ios_version)
        cls.assert_can_handle_akamai_request_for_device(device)

        if device == 'ios':
            version = ios_version

        data_class = cls.h2_mapping[device]
        akamai_str = cls._find_version_from_given_dict(version, data_class.akamai_versions, flag=flag)

        if akamai_str is None:
            if device == 'ios':
                error_with_version = f"{cls.name} on iOS version {ios_version}"
            elif cls.chromium:
                error_with_version = f"{device} {cls.name} based on chromium version {version}"
            else:
                error_with_version = f"{device} {cls.name} version {version}"

            raise ValueError(f"no matching akamai string found in database for " + error_with_version)

        return akamai_str

    @classmethod
    def _find_version_from_given_dict(cls, version: int, d: dict, flag=Flags.REASONABLE):

        closest = None
        min_dif = float('inf')

        for version_bounds, value in d.items():
            if '-' not in version_bounds:
                lower_bound = upper_bound = int(version_bounds)
            else:
                lower_bound, upper_bound = map(int, version_bounds.split('-'))

            if lower_bound <= version <= upper_bound:
                return value
            else:
                if abs(lower_bound - version) < min_dif:
                    min_dif = abs(lower_bound - version)
                    closest = value
                if abs(upper_bound - version) < min_dif:
                    min_dif = abs(upper_bound - version)
                    closest = value

        if min_dif <= cls.reasonable and flag == Flags.REASONABLE:
            return closest

        return None

    @classmethod
    def get_chromium_version(cls, user_agent: str):
        full = re.search(cls.chromium_pattern, user_agent).group(1)
        major = int(full.split('.')[0])
        return major

    @classmethod
    def assert_ios_version_correct(cls, device: str, ios_version: int):
        if device == 'ios' and not ios_version:
            raise ValueError("ios_version not supplied even though device requested was iOS")

        if ios_version and not isinstance(ios_version, int):
            raise ValueError("ios_version should be n valid integer denoting only the major. For example, "
                             "use 13 to denote iOS version 13.5")

    @classmethod
    def assert_can_handle_akamai_request_for_device(cls, device: str):
        try:
            data_class = cls.h2_mapping[device]
        except KeyError:
            raise ValueError(f"unknown device identifier str '{device}'")

        if data_class is None:
            raise ValueError(f'unsupported device "{device}" provided for browser "{cls.name}"')

    @classmethod
    def assert_flags_ok(cls, flag: int):
        if flag not in Flags:
            raise ValueError("unknown flag provided")


class Chromium(Browser):
    name = None
    chromium = True
    ja3_versions = {

        '111-114': '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,'
                   '51-35-13-16-5-11-17513-0-23-18-45-65281-27-43-10,29-23-24,0',
        '83-110': '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,'
                  '0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '73-82': '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,'
                 '0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0',
    }
    h2_mapping = {
        'desktop': ChromiumDesktop,
        'android': ChromiumMobile,
        'ios': SafariMobile
    }


class Opera(Chromium):
    name = 'Opera'


class Edge(Chromium):
    name = 'Edge'


class Chrome(Chromium):
    name = "Chrome"


class Firefox(Browser):
    name = "Firefox"
    ja3_versions = {
        '89-113': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,'
                  '0-23-65281-10-11-35-16-5-34-51-43-13-45-28,29-23-24-25-256-257,0',
        '75-88': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,'
                 '0-23-65281-10-11-35-16-5-51-43-13-45-28,29-23-24-25-256-257,0',
        '65-74': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,'
                 '0-23-65281-10-11-35-16-5-51-43-13-45-28,29-23-24-25-256-257,0',

    }

    h2_mapping = {
        'desktop': FirefoxDesktop,
        'android': FirefoxMobile,
        'ios': SafariMobile
    }


class Safari(Browser):
    reasonable = 1
    name = "Safari"
    ja3_versions = {
        '15-16': '772,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160'
                 '-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24-25,0',
        '14': '772,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171'
              '-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43,29-23-24-25,0',
        '13': '772,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392'
              '-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10,29-23-24-25,0'
    }

    h2_mapping = {
        'desktop': SafariDesktop,
        'android': SafariMobile,
        'ios': SafariMobile
    }


def get_device_and_browser_from_ua(user_agent_str: str):

    device, browser, version, ios_version = None, None, None, None
    parsed_ua = user_agents.parse(user_agent_str)
    ua_os = parsed_ua.os
    ua_browser = parsed_ua.browser

    # First we parse the device and OS details
    if parsed_ua.is_pc:
        device = 'desktop'
    elif parsed_ua.is_tablet or parsed_ua.is_mobile:
        if ua_os.family.lower() == 'android':
            device = 'android'

        elif ua_os.family.lower() == 'ios':
            device = 'ios'
            try:
                ios_version = ua_os.version[0]
            except IndexError:
                raise ValueError("cannot parse iOS version from user agent")

        else:
            raise ValueError(f"unknown mobile OS '{ua_os.family}'")

    else:
        raise ValueError("cannot parse user agent string")

    # Now we parse the browser
    parsed_browser = ua_browser.family.lower()
    for browser_str, b_class in _browser_mapping.items():
        if browser_str in parsed_browser:
            browser = browser_str
            browser_class = b_class
            break

    if not browser:
        raise ValueError(f"unsupported parsed browser '{ua_browser.family}' in user agent")

    # Finally, we get the browser version:
    try:
        version = ua_browser.version[0]
    except IndexError:
        raise ValueError("cannot parse browser version from user agent string")

    # If the browser is chromium, then we need to pass the chromium version, NOT the browser version
    if browser_class.chromium:
        try:
            version = browser_class.get_chromium_version(user_agent_str)
        except (AttributeError, ValueError):
            raise ValueError("could not parse the chromium version from user agent string")

    return device, browser, version, ios_version


def get_browser_data_class(browser: str):
    try:
        return _browser_mapping[browser]
    except KeyError:
        raise ValueError(f"unsupported browser '{browser}' provided")


_browser_mapping = {
    'chrome': Chrome,
    'safari': Safari,
    'edge': Edge,
    'opera': Opera,
    'firefox': Firefox
}



