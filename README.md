# A pure python TLS client that integrates with httpx.

A comprehensive TLS fingerprinting library that seamlessly integrates with httpx for advanced browser impersonation and anti-detection capabilities.

## Purpose

I made this library mostly because there wasn't an open-sourced TLS client written in Python. Because most clients were 
simply ported from another language, they couldn't really integrate with existing python frameworks. As such, httpx-tls 
is not only written in pure python, it is also built from the ground up keeping interoperability in mind. Here are some 
powerful features httpx-tls supports:

1. **TLS Fingerprint**:
httpx-tls uses a fork of tlslite-ng, a pure python implementation of the TLS stack, to perform the TLS Handshake and the subsequent encrypted 
communication. I have added support for all TLS extensions used by current browsers (specified above), including drafts as well. 
All parameters/ciphers/orders that are used to sniff browser details can be spoofed using httpx-tls.

2. **HTTP2 Fingerprint**:
httpx-tls can spoof your HTTP2 fingerprint as well, including all parameters provided inside the akamai whitepaper. This 
also includes the priority frames setting, which many TLS clients simply skip, but which will allow you to mimic firefox like 
browsers as well.

3. **Integration with httpx**:
httpx-tls is designed to be a near drop-in replacement for httpx. You can use it exactly like you use httpx, except for some use 
cases which are summarised later. Internally, httpx-tls does this by introducing thin wrappers to patch critical points 
inside httpx to cover up it's native tls+http2 fingerprint while injecting our own. What this results in is a TLS client that is 
fully supported by a mature, tested connection library with all its high-level features.

4. **True async support**:
httpx-tls is built keeping asynchronous programming in mind. Unlike other TLS client capable of interacting with Python,
httpx-tls properly supports Python's asynchronous libraries without resorting to OS threadpools at all 
(which defeat the whole point of async). Currently, all async libraries (trio, asyncio and anyio) supported by httpx are
supported by httpx-tls as well.

5. **Built-in UA Parsing**:
Unlike traditional TLS clients, httpx-tls does the heavy-lifting for you to create appropriate TLS fingerprints that
match the browser you want. Thanks to a comprehensive database created from scraping years worth of open-sourced changes
in popular browsers (and some manual testing), you simply need to pass in the user-agent string for which you want the
fingerprint for and httpx-tls will automatically use one for the specific device-os-browser combination. Currently,
this built-in parsing is supported for Chromium browsers (Opera, Edge, Chrome), Firefox, and Safari. Both desktop and
mobile devices' (iOS + android) user-agent strings are supported. A full list of supported browser versions can be found
later.

6. **Extensible**:
Browsers and their fingerprints are dynamic and httpx-tls recognizes that. Apart from just parsing user-agents to create
fingerprints automatically, you can also pass in a custom JA3 string for TLS fingerprint or Akamai string for HTTP/2
fingerprint and httpx-tls will use that instead.

7. **Random TLS Extension Order** (Enabled by Default):
httpx-tls automatically randomizes the order of TLS extensions in the ClientHello message to reduce fingerprinting
and make connections less predictable. This anti-detection feature is enabled by default and helps bypass security
systems that rely on specific extension patterns. All required extensions are still sent to maintain full protocol
compatibility, just in a randomized order each time a connection is established.

## Usage

Requirements
```
pip install -r requirements.txt
# or manually install the modified tlslite-ng:
pip install -e tlslite-ng/
```
Other requirements can be found in setup.py

As mentioned before, httpx-tls integrates with httpx and much of its usage is similar. To create fingerprints, use the 
TLSProfile and Http2Profile classes and pass them to the async client during its creation. For example, to use httpx-tls with trio 
and the built-in user-agent parsing (the code is pretty much the same for asyncio as well):
    
```
    from httpx_tls.profiles import TLSProfile, Http2Profile
    from httpx_tls.client import AsyncTLSClient
    import trio
    
    # Decide on a user-agent
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
         'Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.82'
    
    async def main():
    
        # Create TLS and http2 fingerprints using the useragent
        tls_config = TLSProfile.create_from_useragent(ua)
        h2_config = Http2Profile.create_from_useragent(ua)

        # Use AsyncTLSClient provided by httpx-tls
        client = AsyncTLSClient(h2_config=h2_config, tls_config=tls_config, http2=True)

        # Rest of the API is same as httpx
        response = await client.get("https://get.ja3.zone")
        print(response.text)

        await client.aclose()
    
    
    trio.run(main)
```

To use httpx-tls with a custom http2 and TLS fingerprint:

```
    from httpx_tls.profiles import TLSProfile, Http2Profile
    from httpx_tls.client import AsyncTLSClient
    import trio
    
    # Store the fingerprints strings
    ja3 = '772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,'
          '51-35-13-16-5-11-17513-0-23-18-45-65281-27-43-10,29-23-24,0'
    akamai_str = '1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s'
    
    async def main():
    
        # Create TLS and http2 fingerprints using the stored strings
        tls_config = TLSProfile.create_from_ja3(ja3)
        h2_config = Http2Profile.create_from_akamai_str(akamai_str)

        # Use AsyncTLSClient provided by httpx-tls
        client = AsyncTLSClient(h2_config=h2_config, tls_config=tls_config, http2=True)

        # Rest of the API is same as httpx
        response = await client.get("https://get.ja3.zone")
        print(response.text)

        await client.aclose()
    
    
    trio.run(main)
```

### Random TLS Extension Order

By default, httpx-tls randomizes the order of TLS extensions to improve anti-detection. This feature is **enabled by default**.

To **disable** randomization if you need exact JA3 fingerprint matching:

```python
from httpx_tls.profiles import TLSProfile
from httpx_tls.client import AsyncTLSClient

# Disable randomization in TLSProfile
tls_config = TLSProfile.create_from_ja3(ja3, randomize_extensions=False)

# Or disable in AsyncTLSClient
client = AsyncTLSClient(
    tls_config=tls_config,
    randomize_tls_extensions=False  # Disable randomization
)
```

**Note**: When randomization is enabled (default), each new connection will have a different extension order,
making your fingerprint less predictable and harder to detect.

## Precautions (read this section before using httpx-tls)

While I designed httpx-tls to not have obscure surprises in its API, there still are a few differences between httpx-tls 
and httpx (mostly because of the underlying third-party dependencies) which are summarised below:

1. **Certificate Verification**:
httpx-tls does no certificate verification at all. Essentially, you can assume that the `verify` parameter when creating
a client will always be equivalent to False. Adding client certificates is a planned feature, but it does not work
right now.

2. **Sync Support**:
Currently, httpx-tls only offers asynchronous support, but sync support is planned for future releases.

3. **TLS 1.2**:
TLS 1.2 is supported by httpx-tls, but is not yet well tested enough. TLS 1.3, the current web standard, is fully
supported and tested.

4. **General Bugs**:
httpx-tls is an ambitious project which currently does not have a comprehensive test-suite. Please report any bugs you encounter through the GitHub issues.


## Supported Browsers

The enhanced fingerprint database now supports a comprehensive range of browser versions:

### Chrome/Chromium
- Versions 73-140
- Desktop and Android variants
- Latest TLS 1.3 extensions and cipher suites

### Firefox
- Versions 65-145
- Desktop and mobile variants
- Support for Firefox-specific TLS extensions

### Safari
- Versions 13-26 (both desktop and iOS)
- Comprehensive iOS Safari fingerprints
- Support for Safari-specific TLS behaviors

### Edge
- Versions 99-140?
- Built on Chromium fingerprints

## Recent Enhancements

- **Random TLS Extension Order** (NEW): Automatic randomization of TLS extensions enabled by default to reduce fingerprinting
- **Expanded Browser Coverage**: Added 30+ new browser version ranges based on curl_cffi fingerprint database
- **Enhanced JA3 Accuracy**: Updated TLS fingerprints with modern extension support
- **Improved Anti-Detection**: Successfully bypasses Cloudflare protection on sites like audiobooks.com
- **Modified tlslite-ng**: Custom TLS library with precise cipher/extension order control

## Special Thanks To

- [charxhit](https://github.com/charxhit) for the original [httpx-tls](https://github.com/charxhit/httpx-tls)
- [tlsfuzzer](https://github.com/tlsfuzzer) for the original [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng)
- [lexiforest](https://github.com/lexiforest) for [curl_cffi](https://github.com/lexiforest/curl_cffi) fingerprint database insights
- [encode](https://github.com/encode) for [httpx](https://github.com/encode/httpx)