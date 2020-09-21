#ifndef GEMINI_UTIL_H
#define GEMINI_UTIL_H

struct pathspec {
	const char *var;
	const char *path;
};

char *getpath(const struct pathspec *paths, size_t npaths);
int mkdirs(char *path, mode_t mode);

#endif
