all : multi_block

multi_block : main.o
			g++ -g -o multi_block main.o -lnetfilter_queue

main.o :
			g++ -g -c -o main.o main.cpp

clean :
			rm -f multi_block
			rm -f *.o
