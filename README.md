# MacroMagnet Service

This service analyzes and emulates VBA macros contained in Microsoft Office files.

### Execution

MacroMagnet uses ViperMonkey (https://github.com/decalage2/ViperMonkey) for analysis/emulation. This service will report the following:

1. All discovered actions including entry points. Able to decode base64 encoded commands.

2. Any VBA built-in functions used.

3. Detected URLs, URIs, and IP addresses.

3. Tags:

    NET_IP
    NET_FULL_URI
    NET_PORT
    BASE64_ALPHABET
    SHELLCODE
    