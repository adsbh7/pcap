all : pcap_test

pcap_test: test.o
	g++ -g -o pcap_test test.o -lpcap

test.o:
	g++ -g -c -o test.o test.c

clean:
	rm -f pcap_test
	rm -f *.o

