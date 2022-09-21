LDLIBS += -lpcap

all: pcap_test

pcap-test: pcap_test.c

clean:
	rm -f pcap_test
	rm -f *.o