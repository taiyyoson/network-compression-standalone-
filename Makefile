PROG = compdetect
OBJS = standalone.o cJSON.o

%.o : %.c 
	gcc -c -g -o $@ $< 
$(PROG):$(OBJS)
	gcc -g -o $@ $^ -pthread
clean:
	rm -rf $(OBJS) $(PROG)