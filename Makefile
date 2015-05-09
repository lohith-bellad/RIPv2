default:
	gcc -Wall test.c router.c -lpthread
func:
	gcc -Wall test.c router.c -lpthread -DFUNCTION_DEMO
#test.o:test.c
#	gcc -g -Wall -c -o test.o test.c
#router.o:router.c router.h
#	gcc -g -Wall -c -o router.o router.c
clean:
	rm *.out
