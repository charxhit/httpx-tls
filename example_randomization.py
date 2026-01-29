"""
Example demonstrating random TLS extension order feature (enabled by default)
"""
from httpx_tls.profiles import TLSProfile

print("="*70)
print("Random TLS Extension Order - Enabled by Default")
print("="*70)

ja3 = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,' \
      '51-23-17513-13-45-65281-5-43-27-11-10-18-35-0-16-21,29-23-24,0'

# Example 1: Default behavior (randomization enabled)
print("\n1. Default Behavior - Randomization Enabled")
print("-" * 70)
print("Creating 3 profiles from the same JA3 string:")
for i in range(3):
    profile = TLSProfile.create_from_ja3(ja3)
    print(f"  Profile {i+1}: {profile.settings.extension_order[:8]}...")

# Example 2: Explicitly disable randomization
print("\n2. Disabling Randomization - Exact JA3 Matching")
print("-" * 70)
print("Creating 3 profiles with randomization disabled:")
for i in range(3):
    profile = TLSProfile.create_from_ja3(ja3, randomize_extensions=False)
    print(f"  Profile {i+1}: {profile.settings.extension_order[:8]}...")
print("  All profiles have identical extension order!")

# Example 3: Using with browser versions
print("\n3. Browser Version Profiles (Randomization Enabled by Default)")
print("-" * 70)
chrome_profile = TLSProfile.create_from_version('chrome', 120)
print(f"  Chrome 120: {chrome_profile.settings.extension_order[:6]}...")

firefox_profile = TLSProfile.create_from_version('firefox', 115)
print(f"  Firefox 115: {firefox_profile.settings.extension_order[:6]}...")

# Example 4: Direct instantiation
print("\n4. Direct Instantiation")
print("-" * 70)
print("With randomization (default):")
for i in range(2):
    profile = TLSProfile(
        tls_version=(3, 4),
        ciphers=[4865, 4866, 4867],
        extensions=[51, 23, 13, 45, 65281, 5, 43],
        groups=[29, 23, 24]
    )
    print(f"  Run {i+1}: {profile.settings.extension_order}")

print("\nWithout randomization:")
profile = TLSProfile(
    tls_version=(3, 4),
    ciphers=[4865, 4866, 4867],
    extensions=[51, 23, 13, 45, 65281, 5, 43],
    groups=[29, 23, 24],
    randomize_extensions=False
)
print(f"  Fixed: {profile.settings.extension_order}")

# Summary
print("\n" + "="*70)
print("Summary:")
print("="*70)
print("- Random TLS extension order is ENABLED BY DEFAULT")
print("- Each new profile gets a unique randomized extension order")
print("- This helps avoid fingerprinting and detection")
print("- All required extensions are still sent, just in random order")
print("- Disable with randomize_extensions=False for exact JA3 matching")
print("="*70)
