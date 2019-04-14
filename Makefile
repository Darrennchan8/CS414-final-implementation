all:
	gcc cat.c -o cat -Wall
	gcc hijack.c -o hijack -Wall

clean:
	rm cat hijack

