all: clean Bubblesort

Bubblesort: Bubblesort.o 
	gcc -g -m32 -Wall -o Bubblesort Bubblesort.o  

Bubblesort.o: Bubblesort.c
	gcc -m32 -g -Wall -c -o Bubblesort.o Bubblesort.c 

.PHONY: clean 

clean:
	rm -f *.o	
