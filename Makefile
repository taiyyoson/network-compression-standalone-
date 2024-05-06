PROG = compdetect
OBJS = standalone

%.o : %.c 
	gcc -c -g -o $@ $< 
$(PROG):$(OBJS).o
	gcc -g -o $@ $^ -ljansson -lpthreads
clean:
	rm -rf $(OBJS).o $(PROG)