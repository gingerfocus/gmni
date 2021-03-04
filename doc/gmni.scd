gmni(1)

# NAME

gmni - Gemini client

# SYNPOSIS

*gmni* [-46lLiIN] [-j _mode_] [-E _path_] [-d _input_] [-D _path_] _gemini://..._

# DESCRIPTION

*gmni* executes a gemini request and, if successful, prints the response body
to stdout.

If an error is returned, information is printed to stderr and the process exits
with a non-zero exit status equal to the response status. If a response is
returned which is neither successful or an error, the response status and meta
text are printed to stderr.

If the server requests user input, a prompt is shown and a second request is
performed with the user's input supplied to the server.

# OPTIONS

*-4*
	Force the connection to use IPv4.

*-6*
	Force the connection to use IPv6.

*-d* _input_
	If the server requests user input, a second request is performed with
	the given input string as the user input.

*-D* _path_
	If the server requests user input, _path_ is opened and read, and a
	second request is performed with the contents of _path_ as the user
	input.

*-E* _path_:_key_
	Sets the path to the client certificate and private key file to use,
	both PEM encoded.

*-l*
	For *text/\** responses, *gmni* normally adds a line feed if stdout is a
	TTY and the response body does not include one. This flag suppresses
	this behavior.

*-L*
	Follow redirects.

*-j* _mode_
	Sets the TOFU (trust on first use) configuration, which controls if the
	client shall trust new certificates. _mode_ can be one of *always*,
	*once*, or *fail*.

*-i*
	Print the response status and meta text to stdout.

*-I*
	Print the response status and meta text to stdout, and suppress the
	printing of the response body to stdout.

*-N*
	Suppress the input prompt if the server requests an input, and instead
	print a diagnostic message and exit with a zero (successful) status
	code.

*-o* _path_
	Write output to _path_. If _path_ ends with a '/', the basename of the URL
	will be appended. If _path_ is the empty string, "./" will be presumed.
