
default: all

all: termmines anyptracer

termmines: termmines.c
	$(CC) -O2 -o $@ $^ -lncurses
	strip -Kmain -K_main $@

termmines-dev: termmines.c
	$(CC) -O0 -g -o $@ $^ -lncurses

anyptracer: anyptracer.c
	$(CC) -o $@ $^
