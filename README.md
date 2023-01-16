# gmni - A Gemini client

**Notice**: This project is no longer maintained.

This is a [Gemini](https://gemini.circumlunar.space/) client. Included are:

- A CLI utility (like curl): gmni
- A [line-mode browser](https://en.wikipedia.org/wiki/Line_Mode_Browser): gmnlm

Dependencies:

- A POSIX-like system and a C11 compiler
- [BearSSL](https://www.bearssl.org/index.html)
- [scdoc](https://sr.ht/~sircmpwn/scdoc/) (optional)

Features:

- Page history
- Regex searches
- Bookmarks

[![Screenshot of the line-mode browser](https://l.sr.ht/7kaA.png)](https://asciinema.org/a/Y7viodM01e0AXYyf40CwSLAVA)

## Compiling

```
$ mkdir build && cd build
$ ../configure
$ make
# make install
```

## Usage

See `gmni(1)`, `gmnlm(1)`.
