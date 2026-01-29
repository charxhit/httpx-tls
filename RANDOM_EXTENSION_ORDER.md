# Random TLS Extension Order Feature

## Overview

Random TLS extension order is **enabled by default** in httpx-tls. This feature randomizes the order of TLS extensions in the ClientHello message to help avoid fingerprinting and make connections less predictable while maintaining full protocol compatibility.

## Why Randomize Extension Order?

TLS fingerprinting tools and WAFs often use the specific order of TLS extensions as part of their fingerprinting process. By randomizing the extension order:

- **Reduces fingerprinting**: Each connection can have a different extension order
- **Maintains compatibility**: All required extensions are still sent, just in random order
- **Bypasses detection**: Some security systems key on specific extension patterns

## Usage

### Default Behavior (Randomization Enabled)

By default, all TLS profiles have randomization enabled:

```python
from httpx_tls import AsyncTLSClient
from httpx_tls.profiles import TLSProfile

# Randomization is enabled by default
client = AsyncTLSClient(
    tls_config=TLSProfile.create_from_version('chrome', 120)
)

# Or with JA3 string
profile = TLSProfile.create_from_ja3(ja3)  # Randomization enabled by default

# Or with user agent
profile = TLSProfile.create_from_useragent(user_agent)  # Randomization enabled by default
```

### Disabling Randomization (for exact JA3 matching)

If you need exact JA3 fingerprint matching, you can disable randomization:

```python
from httpx_tls.profiles import TLSProfile
from httpx_tls import AsyncTLSClient

# Disable in TLSProfile creation
profile = TLSProfile.create_from_ja3(ja3, randomize_extensions=False)

# Or when creating from version
profile = TLSProfile.create_from_version('chrome', 120, randomize_extensions=False)

# Or in AsyncTLSClient
client = AsyncTLSClient(
    tls_config=profile,
    randomize_tls_extensions=False
)
```

### Direct TLSProfile Instantiation

```python
from httpx_tls.profiles import TLSProfile

# With randomization (default)
profile = TLSProfile(
    tls_version=(3, 4),
    ciphers=[4865, 4866, 4867],
    extensions=[51, 23, 13, 45, 65281, 5, 43],
    groups=[29, 23, 24]
    # randomize_extensions=True is the default
)

# Without randomization
profile = TLSProfile(
    tls_version=(3, 4),
    ciphers=[4865, 4866, 4867],
    extensions=[51, 23, 13, 45, 65281, 5, 43],
    groups=[29, 23, 24],
    randomize_extensions=False
)
```

## Example Output

**Without randomization:**
```
Extensions: [51, 23, 13, 45, 65281, 5, 43]
```

**With randomization (3 different runs):**
```
Run 1: [13, 23, 43, 65281, 51, 5, 45]
Run 2: [43, 45, 5, 13, 23, 65281, 51]
Run 3: [45, 23, 51, 13, 65281, 5, 43]
```

## Implementation Details

### Changes Made

1. **profiles.py**:
   - Added `randomize_extensions` parameter to `TLSProfile.__init__()`
   - Implemented `_randomize_extension_order()` method
   - Updated `_set_order()` to apply randomization and enable `extension_order`
   - Re-enabled the previously commented-out `settings.extension_order` assignment

2. **client.py**:
   - Added `randomize_tls_extensions` parameter to `AsyncTLSClient.__init__()`
   - Automatically applies randomization flag to TLSProfile if provided

### Technical Notes

- Extension randomization uses Python's `random.shuffle()` for unpredictable ordering
- All extensions from the original profile are preserved, only the order changes
- The randomization happens at profile creation time
- Each new TLSProfile instance with randomization enabled will have a different order

## Security Considerations

- **Compatibility**: Randomizing extension order is generally safe and maintains TLS protocol compatibility
- **Fingerprint Variation**: Each connection will have a unique fingerprint when randomization is enabled
- **Performance**: Minimal overhead - randomization happens once during profile creation

## Testing

Run the included test and example scripts:

```bash
# Run basic tests
python test_randomization.py

# Run usage examples
python example_random_extensions.py
```

## Related Files

- [profiles.py](httpx_tls/profiles.py) - TLS profile implementation with randomization
- [client.py](httpx_tls/client.py) - AsyncTLSClient with randomization support
- [test_randomization.py](test_randomization.py) - Test script
- [example_random_extensions.py](example_random_extensions.py) - Usage examples
