all: clean AntiVirus

AntiVirus: AntiVirus.o 
	gcc -g -m32 -Wall -o AntiVirus AntiVirus.o  

AntiVirus.o: AntiVirus.c
	gcc -m32 -g -Wall -c -o AntiVirus.o AntiVirus.c 

.PHONY: clean 

clean:
	rm -f *.o	
