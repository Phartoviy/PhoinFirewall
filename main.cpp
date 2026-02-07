#include "sniffer.h"

#include <iostream>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::fprintf(stderr,
                     "Usage:\n"
                     "  %s -l              # list interfaces\n"
                     "  %s <iface>         # sniff all packets on iface\n", argv[0], argv[0]);
        return 1;
    }

    if (std::strcmp(argv[1], "-l") == 0) {
        list_devs();
        return 0;
    }

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]{0};

    // snaplen=65535, promisc=1, timeout=1000ms
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    int linktype = pcap_datalink(handle);
    if (linktype != DLT_EN10MB) { // Ethernet
        std::fprintf(stderr, "Unsupported datalink (%d). This example expects Ethernet (DLT_EN10MB).\n", linktype);
        pcap_close(handle);
        return 1;
    }

    std::printf("Sniffing on %s... (Ctrl+C to stop)\n", dev);

    // Capture indefinitely; callback prints each packet
    int rc = pcap_loop(handle, 0, packet_handler, nullptr);
    if (rc == PCAP_ERROR) {
        std::fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}
