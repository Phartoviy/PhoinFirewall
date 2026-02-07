#include "sniffer.h"

#include <iostream>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::fprintf(stderr,
                     "Usage:\n"
                     "  %s -l\n"
                     "  %s <iface> [--apply] [--fw nft|iptables] [--block-seconds N] [--enable-amp-shield]\n",
                     argv[0], argv[0]);
        return 1;
    }
    if (std::strcmp(argv[1], "-l") == 0) { list_devs(); return 0; }

    Config cfg;
    cfg.fw = FWBackend::NFT;

    const char* iface = argv[1];
    for (int i=2;i<argc;i++){
        if (std::strcmp(argv[i], "--apply") == 0) cfg.apply = true;
        else if (std::strcmp(argv[i], "--fw") == 0 && i+1<argc) cfg.fw = parse_fw(argv[++i]);
        else if (std::strcmp(argv[i], "--block-seconds") == 0 && i+1<argc) cfg.block_seconds = std::max(10, std::atoi(argv[++i]));
        else if (std::strcmp(argv[i], "--enable-amp-shield") == 0) cfg.enable_amp_shield = true;
    }
    if (!cfg.apply) cfg.fw = FWBackend::NONE;

    char errbuf[PCAP_ERRBUF_SIZE]{0};
    pcap_t* handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if (!handle) {
        std::fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::fprintf(stderr, "Unsupported datalink. Need Ethernet (DLT_EN10MB).\n");
        pcap_close(handle);
        return 1;
    }

    if (cfg.use_bpf_filter) {
        // IPv4 TCP/UDP only (reduces load). We care about UDP amp and TCP web.
        const char* filter = "ip and (udp or tcp)";
        bpf_program fp{};
        if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle, &fp);
            pcap_freecode(&fp);
        } else {
            std::fprintf(stderr, "pcap_compile failed, continuing: %s\n", pcap_geterr(handle));
        }
    }

    State st;
    st.cfg = cfg;

    std::printf("Combo DDoS-guard sniffing on %s...\n", iface);
    std::printf("Mode: %s\n", cfg.apply ? "detect+mitigate" : "detect-only");
    if (cfg.apply) {
        std::printf("FW: %s, block=%ds, amp-shield=%s\n",
                    (cfg.fw==FWBackend::NFT?"nft":"iptables"),
                    cfg.block_seconds,
                    cfg.enable_amp_shield ? "ON" : "OFF");
    }

    int rc = pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&st));
    if (rc == PCAP_ERROR) std::fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return 0;
}
