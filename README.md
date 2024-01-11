# SEPROM Panic Decrypt

## Dependencies:
`pip3 install pycryptodome`

## Usage:
`python3 main.py <SoC> <SEPROM Panic Bytes>`

## Example:
```bash
panic(cpu 0 caller 0xfffffff0219d867c): "SEP ROM boot panic. 0xB9FD8EA50D398BCBA905C2EC0647846B4F1C4EEAB64B4BE947098F1A0AF1EB23B26493A7A78634E2A05034A5377296A383CBF3165A44861C" @SEPROMPanicBuffer.cpp:71
```

```bash
❯ python3 ./SEPROMPanicDecrypt/main.py s8000 0xB9FD8EA50D398BCBA905C2EC0647846B4F1C4EEAB64B4BE947098F1A0AF1EB23B26493A7A78634E2A05034A5377296A383CBF3165A44861C
0x000000FF
0x000000A5
0x100056C3
0x10007723
0x100056C3
0x10007723
0x10005795
0x10004D0B
0x00000000
0x00000000
0x00000000
0x00000000
❯
```

## Supported SoC's:
* a8
* a8x
* a9(Samsung)
* a9x
* a9(TSMC)
* S4/S5
* a10
* a10x
* a12
* a12z/x
* a14
* M1
* a15
* M2

## Unsupported SoC's:
* T2 Chip
* a11
* a13
* a16
* M3
* a17