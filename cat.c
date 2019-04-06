#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

char* getFileContents(char* fileName) {
	FILE * fp = fopen(fileName, "r");
	if(!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	size_t fileLength = (size_t) ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *fStart = malloc(fileLength);
	fread(fStart, 1, fileLength, fp);
	fclose(fp);
	return fStart;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s filepaths\n", argv[0]);
		return -1;
	}
	char *fileContents = getFileContents(argv[1]);
	if (!fileContents) {
		fprintf(stderr, "Unable to read %s\n", argv[1]);
		return 1;
	}
	printf("%s\n", fileContents);
	return 0;
}
