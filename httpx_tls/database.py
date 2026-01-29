import re
from .constants import Flags

__all__ = [
    "Chrome",
    "Firefox",
    "Safari",
    "get_browser_data_class",
    "get_device_and_browser_from_ua"
]


class Http2Data:
    akamai_versions = {}


class ChromiumDesktop(Http2Data):
    akamai_versions = {
        '137-144': '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
        '130-136': '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '120-131': '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '115-119': '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '106-114': '1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '99-105': '1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '80-98': '1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p',
        '73-79': '1:65536,3:1000,4:6291456|15663105|0|m,a,s,p',
    }


class ChromiumMobile(ChromiumDesktop):
    pass


class FirefoxDesktop(Http2Data):
    akamai_versions = {
        '136-146': '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
        '133-135': "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        '120-132': "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        '65-119': "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
    }


class FirefoxMobile(Http2Data):
    akamai_versions = {
        '136-146': '1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s',
        '133-135': "1:4096,4:32768,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        '120-132': "1:4096,4:32768,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
        '65-119': "1:4096,4:32768,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
    }


class SafariDesktop(Http2Data):
    akamai_versions = {
        '18-26': "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
        '17': "4:4194304,3:100|10485760|0|m,s,p,a",
        '15-16': "4:4194304,3:100|10485760|0|m,s,p,a",
        '14': "4:4194304,3:100|10485760|0|m,s,p,a",
        '13': "4:1048576,3:100|10485760|0|m,s,p,a",
    }


class SafariMobile(Http2Data):
    akamai_versions = {
        '26': '2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p',
        '17-18': "2:0;4:2097152;3:100|10485760|0|m,s,p,a",
        '15-16': "4:2097152,3:100|10485760|0|m,s,p,a",
        '14': "4:2097152,3:100|10485760|0|m,s,p,a",
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
    chromium_pattern = re.compile(r'(?:Chrome|CriOS|EdgiOS)/(.+?)(?: |$)')
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
        match = re.search(cls.chromium_pattern, user_agent)
        if not match:
            raise ValueError(f"Could not find Chrome/CriOS/EdgiOS version in user agent: {user_agent}")
        full = match.group(1)
        major = int(full.split('.')[0])
        return major

    @classmethod
    def assert_ios_version_correct(cls, device: str, ios_version: int):
        if device == 'ios' and not ios_version:
            raise ValueError("ios_version not supplied even though device requested was iOS")

        if ios_version and not isinstance(ios_version, int):
            raise ValueError("ios_version should be n valid integer denoting only the major. For example, use 13 to denote iOS version 13.5")

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


class Chrome(Browser):
    name = "Chrome"
    chromium = True
    ja3_versions = {
        '137-144': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-5-51-35-13-16-18-65281-45-27-0-23-43-65037-11-17613,4588-29-23-24,0',
        '120-136': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25,0',
        '116-119': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24-25,0',
        '110-115': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '104-109': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '100-103': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '99': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '83-98': '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        '73-82': '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0',
    }
    h2_mapping = {
        'desktop': ChromiumDesktop,
        'android': ChromiumMobile,
        'ios': SafariMobile
    }

class Firefox(Browser):
    name = "Firefox"
    ja3_versions = {
        '136-146': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
        '133-135': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0',
        '120-132': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28,29-23-24-25-256-257,0',
        '114-119': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28,29-23-24-25-256-257,0',
        '89-113': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28,29-23-24-25-256-257,0',
        '75-88': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28,29-23-24-25-256-257,0',
        '65-74': '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28,29-23-24-25-256-257,0',
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
        '26': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-30-24-25,0',
        '17-18': '771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-30-24-25,0',
        '15-16': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
        '15': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
        '14': '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
        '13': '771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0'
    }

    h2_mapping = {
        'desktop': SafariDesktop,
        'android': SafariMobile,
        'ios': SafariMobile
    }

def get_device_and_browser_from_ua(user_agent_str: str):
    """
    Simplified UA parser that detects only browser cores (Chromium, Firefox, Safari).
    Returns device type, browser core, version, and iOS version if applicable.
    """
    device, browser, version, ios_version = None, None, None, None
    ua_lower = user_agent_str.lower()

    # Detect device type and OS
    if 'mobile' in ua_lower or 'android' in ua_lower:
        if 'android' in ua_lower:
            device = 'android'
        elif 'iphone' in ua_lower or 'ipad' in ua_lower:
            device = 'ios'
            # Parse iOS version
            ios_match = re.search(r'OS (\d+)[_\d]*', user_agent_str, re.IGNORECASE)
            if ios_match:
                ios_version = int(ios_match.group(1))
            else:
                raise ValueError("cannot parse iOS version from user agent")
        else:
            # Generic mobile, assume Android
            device = 'android'
    elif 'ipad' in ua_lower or 'iphone' in ua_lower:
        device = 'ios'
        ios_match = re.search(r'OS (\d+)[_\d]*', user_agent_str, re.IGNORECASE)
        if ios_match:
            ios_version = int(ios_match.group(1))
        else:
            raise ValueError("cannot parse iOS version from user agent")
    else:
        # Desktop
        device = 'desktop'

    # Detect browser core - order matters!
    # Check for Firefox first (not Chromium-based)
    if 'firefox' in ua_lower or 'fxios' in ua_lower:
        if device == 'ios':
            # Firefox on iOS uses WebKit, treat as Safari
            browser = 'safari'
            version = ios_version
        else:
            browser = 'firefox'
            # Parse Firefox version
            firefox_match = re.search(r'Firefox/(\d+)', user_agent_str, re.IGNORECASE)
            if firefox_match:
                version = int(firefox_match.group(1))
            else:
                raise ValueError("cannot parse Firefox version from user agent")

    # Check for Chromium-based browsers (Chrome, Edge, etc.)
    elif 'chrome' in ua_lower or 'crios' in ua_lower or 'edg' in ua_lower or 'chromium' in ua_lower:
        if device == 'ios':
            # All browsers on iOS use WebKit
            browser = 'safari'
            version = ios_version
        else:
            browser = 'chrome'
            # Parse Chromium version
            chrome_match = re.search(r'(?:Chrome|CriOS|Edg|Chromium)/(\d+)', user_agent_str, re.IGNORECASE)
            if chrome_match:
                version = int(chrome_match.group(1))
            else:
                raise ValueError("cannot parse Chromium version from user agent")

    # Check for Safari/WebKit (on iOS or macOS) - must come after Chrome/Firefox checks
    elif device == 'ios' or ('safari' in ua_lower and 'chrome' not in ua_lower and 'crios' not in ua_lower):
        browser = 'safari'

        # Parse Safari version from Version/ string
        safari_match = re.search(r'Version/(\d+)', user_agent_str, re.IGNORECASE)
        if safari_match:
            version = int(safari_match.group(1))
        else:
            # No Version/ string found - if iOS, use OS version (e.g., Google App)
            if device == 'ios':
                version = ios_version
            else:
                raise ValueError("cannot parse Safari version from user agent")

    else:
        raise ValueError(f"cannot detect browser core from user agent: {user_agent_str}")

    if not version:
        raise ValueError("cannot parse browser version from user agent")

    return device, browser, version, ios_version


def get_browser_data_class(browser: str):
    try:
        return _browser_mapping[browser]
    except KeyError:
        raise ValueError(f"unsupported browser '{browser}' provided")


_browser_mapping = {
    'chrome': Chrome,
    'safari': Safari,
    'firefox': Firefox,
}