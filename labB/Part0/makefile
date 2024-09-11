all: clean Part0

Part0: Part0.o 
	gcc -g -m32 -Wall -o Part0 Part0.o  

Part0.o: Part0.c
	gcc -m32 -g -Wall -c -o Part0.o Part0.c 

.PHONY: clean 

clean:
	rm -f *.o	
