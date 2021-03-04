#include <assert.h>
#include <bearssl_ssl.h>
#include <errno.h>
#include <gmni/gmni.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"

static void
posix_dirname(char *path, char *dname)
{
	char p[PATH_MAX+1];
	char *t;

	assert(strlen(path) <= PATH_MAX);

	strcpy(p, path);
	t = dirname(p);
	memmove(dname, t, strlen(t) + 1);
}

/** Make directory and all of its parents */
int
mkdirs(char *path, mode_t mode)
{
	char dname[PATH_MAX + 1];
	posix_dirname(path, dname);
	if (strcmp(dname, "/") == 0) {
		return 0;
	}
	if (mkdirs(dname, mode) != 0) {
		return -1;
	}
	if (mkdir(path, mode) != 0 && errno != EEXIST) {
		return -1;
	}
	errno = 0;
	return 0;
}

char *
getpath(const struct pathspec *paths, size_t npaths) {
	for (size_t i = 0; i < npaths; i++) {
		const char *var = "";
		if (paths[i].var) {
			var = getenv(paths[i].var);
		}
		if (var) {
			char *out = calloc(1,
				strlen(var) + strlen(paths[i].path) + 1);
			strcat(strcat(out, var), paths[i].path);
			return out;
		}
	}
	return NULL;
}

int
download_resp(FILE *out, struct gemini_response resp, const char *path,
		char *url)
{
	char path_buf[PATH_MAX];
	assert(path);
	if (path[0] == '\0') {
		path = "./";
	}
	if (path[strlen(path)-1] == '/') {
		int n = snprintf(path_buf, sizeof(path_buf), "%s%s", path, basename(url));
		assert((size_t)n < sizeof(path_buf));
		path = path_buf;
	}
	FILE *f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr, "Could not open %s for writing: %s\n",
			path, strerror(errno));
		return 1;
	}
	fprintf(out, "Downloading %s to %s\n", url, path);
	char buf[BUFSIZ];
	for (int n = 1; n > 0;) {
		n = br_sslio_read(&resp.body, buf, sizeof(buf));
		if (n == -1) {
			fprintf(stderr, "Error: read\n");
			return 1;
		}
		ssize_t w = 0;
		while (w < (ssize_t)n) {
			ssize_t x = fwrite(&buf[w], 1, n - w, f);
			if (ferror(f)) {
				fprintf(stderr, "Error: write: %s\n",
					strerror(errno));
				return 1;
			}
			w += x;
		}
	}
	fprintf(out, "Finished download\n");
	fclose(f);
	return 0;
}
