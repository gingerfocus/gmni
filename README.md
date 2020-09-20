# gmni - A Gemini client

This is a [Gemini](https://gemini.circumlunar.space/) client. Included are:

- A CLI utility (like curl): gmni
- A [line-mode browser](https://en.wikipedia.org/wiki/Line_Mode_Browser): gmnlm

Dependencies:

- A POSIX-like system and a C11 compiler
- OpenSSL
- [scdoc](https://sr.ht/~sircmpwn/scdoc/) (optional)

## Compiling

```
$ mkdir build && cd build
$ ../configure
$ make
# make install
```

## Usage

See `gmni(1)`, `gmnlm(1)`.
