PROG = compdetect
OBJS = standalone

%.o : %.c 
	gcc -c -g -o $@ $< 
$(PROG):$(OBJS).o
	gcc -g -o $@ $^ -ljansson -pthread
clean:
	rm -rf $(OBJS).o $(PROG)