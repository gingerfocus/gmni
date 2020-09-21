# gmni - A Gemini client

This is a [Gemini](https://gemini.circumlunar.space/) client. Included are:

- A CLI utility (like curl): gmni
- A [line-mode browser](https://en.wikipedia.org/wiki/Line_Mode_Browser): gmnlm

[![Screenshot of the line-mode browser](https://l.sr.ht/AY7_.png)](https://asciinema.org/a/ldo2gV7qiDoBXvGwuD6x1jbn3)

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
