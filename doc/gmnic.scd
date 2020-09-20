gmnic(1)

# NAME

gmnic - Gemini client

# SYNPOSIS

*gmnic* [-46lLiIN] [-E _path_] [-d _input_] [-D _path_] _gemini://..._

# DESCRIPTION

*gmnic* executes a gemini request and, if successful, prints the response body
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

*-E* _path_[:_password_]
	Sets the path to the client certificate to use (and optionally a
	password). If the filename contains ":" but the certificate does not
	accept a password, append ":" to the path and it will be intepreted as
	an empty password.

*-l*
	For *text/\** responses, gmnic normally adds a line feed if stdout is a
	TTY and the response body does not include one. This flag suppresses
	this behavior.

*-L*
	Follow redirects.

*-i*
	Print the response status and meta text to stdout.

*-I*
	Print the response status and meta text to stdout, and suppress the
	printing of the response body to stdout.

*-N*
	Suppress the input prompt if the server requests an input, and instead
	print a diagnostic message and exit with a zero (successful) status
	code.
