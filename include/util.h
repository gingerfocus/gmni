#ifndef GEMINI_UTIL_H
#define GEMINI_UTIL_H
#include <stdio.h>
#include <sys/types.h>

struct pathspec {
	const char *var;
	const char *path;
};

char *getpath(const struct pathspec *paths, size_t npaths);
int mkdirs(char *path, mode_t mode);
int download_resp(FILE *out, struct gemini_response resp, const char *path,
		char *url);

#endif
