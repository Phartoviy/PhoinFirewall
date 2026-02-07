#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>

#ifdef __linux__
#include <arpa/inet.h>
#endif

// Ethernet header (14 bytes)
#pragma pack(push, 1)
struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
};

// IPv4 header (min 20 bytes)
struct IPv4Hdr {
    uint8_t  ver_ihl;      // version + IHL
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t hdr_checksum;
    uint32_t src;
    uint32_t dst;
};

// TCP header (min 20 bytes)
struct TCPHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_res;      // data offset in high 4 bits
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
};

// UDP header (8 bytes)
struct UDPHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

static void mac_to_str(const uint8_t mac[6], char out[18]) {
    std::snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static const char* proto_name(uint8_t p) {
    switch (p) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    default: return "OTHER";
    }
}

static void packet_handler(u_char* /*user*/,
                           const struct pcap_pkthdr* h,
                           const u_char* bytes) {
    // Timestamp
    char tbuf[64];
    std::time_t tt = h->ts.tv_sec;
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, (long)h->ts.tv_usec);

    if (h->caplen < sizeof(EthHdr)) return;

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(bytes);
    uint16_t etype = ntohs(eth->type);

    char smac[18], dmac[18];
    mac_to_str(eth->src, smac);
    mac_to_str(eth->dst, dmac);

    std::printf("[%s] len=%u caplen=%u  %s -> %s  eth=0x%04x",
                tbuf, h->len, h->caplen, smac, dmac, etype);

    // Only IPv4 (0x0800)
    if (etype != 0x0800) {
        std::printf("\n");
        return;
    }

    const u_char* ip_ptr = bytes + sizeof(EthHdr);
    size_t ip_avail = h->caplen - sizeof(EthHdr);
    if (ip_avail < sizeof(IPv4Hdr)) {
        std::printf("  IPv4(truncated)\n");
        return;
    }

    const IPv4Hdr* ip = reinterpret_cast<const IPv4Hdr*>(ip_ptr);
    uint8_t version = (ip->ver_ihl >> 4) & 0x0F;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;

    if (version != 4 || ihl < 20 || ip_avail < ihl) {
        std::printf("  IPv4(bad)\n");
        return;
    }

    char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
    in_addr saddr{ip->src};
    in_addr daddr{ip->dst};
    std::snprintf(sip, sizeof(sip), "%s", inet_ntoa(saddr));
    std::snprintf(dip, sizeof(dip), "%s", inet_ntoa(daddr));

    std::printf("  IPv4 %s -> %s  proto=%s",
                sip, dip, proto_name(ip->proto));

    const u_char* l4_ptr = ip_ptr + ihl;
    size_t l4_avail = ip_avail - ihl;

    if (ip->proto == 6) { // TCP
        if (l4_avail >= sizeof(TCPHdr)) {
            const TCPHdr* tcp = reinterpret_cast<const TCPHdr*>(l4_ptr);
            uint16_t sport = ntohs(tcp->src_port);
            uint16_t dport = ntohs(tcp->dst_port);
            std::printf("  %u -> %u", sport, dport);
        } else {
            std::printf("  TCP(truncated)");
        }
    } else if (ip->proto == 17) { // UDP
        if (l4_avail >= sizeof(UDPHdr)) {
            const UDPHdr* udp = reinterpret_cast<const UDPHdr*>(l4_ptr);
            uint16_t sport = ntohs(udp->src_port);
            uint16_t dport = ntohs(udp->dst_port);
            std::printf("  %u -> %u", sport, dport);
        } else {
            std::printf("  UDP(truncated)");
        }
    }

    std::printf("\n");
}

static void list_devs() {
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE]{0};

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        std::fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
        return;
    }

    std::puts("Interfaces:");
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::printf("  %s", d->name ? d->name : "(null)");
        if (d->description) std::printf("  - %s", d->description);
        std::printf("\n");
    }
    pcap_freealldevs(alldevs);
}

#endif // SNIFFER_H
