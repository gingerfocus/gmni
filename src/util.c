#include <assert.h>
#include <bearssl.h>
#include <errno.h>
#include <gmni/gmni.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "util.h"

void
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
	int n = 0;
	assert(path);
	switch (path[0]) {
	case '\0':
		strcpy(path_buf, "./");
		break;
	case '~':
		n = snprintf(path_buf, PATH_MAX, "%s/%s", getenv("HOME"), &path[1]);
		if (n > PATH_MAX) {
			fprintf(stderr,
				"Path %s exceeds limit of %d bytes and has been truncated\n",
				path_buf, PATH_MAX);
			return 1;
		}
		break;
	default:
		if (strlen(path_buf) > PATH_MAX) {
			fprintf(stderr, "Path %s exceeds limit of %d bytes\n",
				path_buf, PATH_MAX);
			return 1;
		}
		strcpy(path_buf, path);
	}
	char path_res[PATH_MAX];
	if (path_buf[strlen(path_buf)-1] == '/') {
		n = snprintf(path_res, PATH_MAX, "%s%s", path_buf, basename(url));
		if (n > PATH_MAX) {
			fprintf(stderr, 
				"Path %s exceeds limit of %d bytes and has been truncated\n",
				path_res, PATH_MAX);
			return 1;
		}
	} else {
		strcpy(path_res, path_buf);
	}
	FILE *f = fopen(path_res, "w");
	if (f == NULL) {
		fprintf(stderr, "Could not open %s for writing: %s\n",
			path_res, strerror(errno));
		return 1;
	}
	fprintf(out, "Downloading %s to %s\n", url, path_res);
	char buf[BUFSIZ];
	for (int n = 1; n > 0;) {
		if (resp.sc) {
			n = br_sslio_read(&resp.body, buf, BUFSIZ);
		} else {
			n = read(resp.fd, buf, BUFSIZ);
		}
		if (n < 0) {
			break;
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
