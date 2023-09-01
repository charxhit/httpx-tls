# A pure python TLS client that integrates with httpx.

Not ready yet, check back soon!

 
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

6. **Extensible**
Browsers and their fingerprints are dynamic and httpx-tls recognizes that. Apart from just parsing user-agents to create 
fingerprints automatically, you can also pass in a custom ja3 string for TLS fingerprint or akamai string for http2 
fingerprint and httpx-tls will use that instead.

## Usage

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
        response = await client.get("https://tools.scrapfly.io/api/fp/ja3")
        print(response.text)
    
    
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
        response = await client.get("https://tools.scrapfly.io/api/fp/ja3")
        print(response.text)
    
    
    trio.run(main)
```

