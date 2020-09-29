gmnlm(1)

# NAME

gmnlm - Gemini line-mode browser

# SYNPOSIS

*gmnlm* [-PU] [-j _mode_] [-W _width_] _gemini://..._

# DESCRIPTION

*gmnlm* is an interactive line-mode Gemini browser.

# OPTIONS

*-j* _mode_
	Sets the TOFU (trust on first use) configuration, which controls if the
	client shall trust new certificates. _mode_ can be one of *always*,
	*once*, or *fail*.

*-P*
	Disable pagination.

*-U*
	Disable conservative use of Unicode symbols to render Gemini layout
	features.

*-W* _width_
	Sets the maximum width, in columns, of Gemtext pages.
