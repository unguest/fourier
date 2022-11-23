# Fourier documentation

## Usage

### Expected use chain

You may first load a binary before running several analysis against it. To do so :

```none
load path\to\binary.exe
basic_information
detect_enumeration
```

1. Load the binary with command `load`
2. Retrieve basic information with the command `basic_information`
3. Check if any of the retreived functions loaded is known as a potential enumeration vector with `detect_enumeration`

I've tried to keep commands names as simple so you should not break your brains (I mean the ones you have left...).

### Detection capabilities

Out for now, the detection capabilities are relying on unobfuscated function calls on the PE. The data has directly been extracted from [https://malapi.io]().

Thus, this program is able to "detect" function calls that may be used for :

- Anti-debugging
- Enumeration
- Evasion
- Injection
- Internet communications
- Spying
- Ransomwares
- Helpers

### Shortcuts

To get faster, you can use several of the existing shortcuts :

- `ld` as an alias for `load`
- `bi` or `basic_info` for `basic_information`
- `den` for `detect_enumeration`

Other shortcuts can be found by reading the code in `src/common/commands.rs` ;).
