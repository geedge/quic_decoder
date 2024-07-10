#pragma once

#define CALLOC(nmemb, size) calloc(nmemb, size)
#define REALLOC(ptr, newsize)  realloc(ptr, newsize)
#define	FREE(p)	{free((void *)p); p = NULL;}