#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

#ifdef __linux__
#include <arpa/inet.h>
#endif

#pragma pack(push, 1)
struct EthHdr { uint8_t dst[6], src[6]; uint16_t type; };

struct IPv4Hdr {
    uint8_t  ver_ihl;
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

struct UDPHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

struct TCPHdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_res;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
};
#pragma pack(pop)

static std::string ip_to_str(uint32_t net) {
    in_addr a{net};
    return std::string(inet_ntoa(a));
}
static int run_cmd(const std::string& cmd) { return std::system(cmd.c_str()); }

enum class FWBackend { NFT, IPTABLES, NONE };

struct RateBucket { uint64_t pkts=0, bytes=0; };
static void reset_bucket(RateBucket& b){ b.pkts=0; b.bytes=0; }

static inline bool starts_with(const std::string& s, const char* pfx){
    return s.rfind(pfx, 0) == 0;
}
static inline bool is_api_path(const std::string& p){
    return starts_with(p, "/api") || starts_with(p, "/v1") || starts_with(p, "/v2") || starts_with(p, "/graphql");
}

// ---------- Config ----------
struct Config {
    bool apply = false;
    FWBackend fw = FWBackend::NONE;
    int block_seconds = 300;

    bool enable_amp_shield = false; // drop udp sport in amp_ports (если не нужен этот трафик на вход)

    // Ports
    uint16_t HTTP_PORT  = 80;
    uint16_t HTTPS_PORT = 443;

    // Amp/reflection source ports (DNS/NTP/SSDP/CLDAP/Memcached/Chargen/SNMP/TFTP/WS-Discovery/NetBIOS/RIP/Portmap/CoAP/mDNS)
    std::unordered_set<uint16_t> amp_sports = {
        53, 123, 1900, 389, 11211, 19, 161, 69, 3702, 137, 520, 111, 5683, 5353
    };

    // ---- Thresholds (подстрой!) ----
    // UDP flood (generic)
    uint64_t UDP_PPS_GLOBAL = 80000;
    uint64_t UDP_BPS_GLOBAL = 400ull * 1024 * 1024;

    uint64_t UDP_PPS_PER_SRC = 6000;
    uint64_t UDP_BPS_PER_SRC = 80ull * 1024 * 1024;

    // Reflection/Amp (udp sport in amp list, payload >= MIN_AMP_PAYLOAD)
    uint32_t MIN_AMP_PAYLOAD = 200;
    uint64_t AMP_PPS_GLOBAL = 30000;
    uint64_t AMP_PPS_PER_SRC = 3000;

    // SYN flood (to HTTP/HTTPS)
    uint64_t SYN_PPS_GLOBAL = 60000;
    uint64_t SYN_PPS_PER_SRC = 4000;

    // HTTP flood (plaintext on 80)
    uint64_t HTTP_RPS_GLOBAL = 25000;
    uint64_t HTTP_RPS_PER_SRC = 300;
    uint64_t API_RPS_PER_SRC  = 150;

    // HTTPS flood (TLS): new conns to 443
    uint64_t TLS_NEWCONN_GLOBAL = 60000;
    uint64_t TLS_NEWCONN_PER_SRC = 250;

    // Slowloris on 80: header not finished within X seconds
    uint64_t SLOW_HDR_TIMEOUT_SEC = 10;
    uint64_t OPEN_HTTP_FLOWS_PER_SRC = 200;

    // TLS “slowloris-like” on 443: too many open conns with tiny bytes
    uint64_t OPEN_TLS_FLOWS_PER_SRC = 300;
    uint64_t TLS_TINY_BYTES_MAX = 300;     // за жизнь соединения получено байт <= этого => “пустая”
    uint64_t TLS_STUCK_AGE_SEC  = 15;      // висит дольше

    bool use_bpf_filter = true;
};

// ---------- Firewall (nftables set timeout) ----------
static FWBackend parse_fw(const char* s) {
    if (!s) return FWBackend::NONE;
    if (std::strcmp(s, "nft") == 0) return FWBackend::NFT;
    if (std::strcmp(s, "iptables") == 0) return FWBackend::IPTABLES;
    return FWBackend::NONE;
}

static void fw_init_if_needed(const Config& cfg) {
    if (!cfg.apply) return;

    if (cfg.fw == FWBackend::NFT) {
        // table/chain
        run_cmd("nft list table inet ddos_guard >/dev/null 2>&1 || nft add table inet ddos_guard");
        run_cmd("nft list chain inet ddos_guard input >/dev/null 2>&1 || nft add chain inet ddos_guard input { type filter hook input priority -150 \\; policy accept \\; }");

        // set with timeout
        run_cmd("nft list set inet ddos_guard blocked4 >/dev/null 2>&1 || nft add set inet ddos_guard blocked4 { type ipv4_addr\\; flags timeout\\; }");
        // rule to drop blocked
        run_cmd("nft list ruleset | grep -q \"ip saddr @blocked4 drop\" || nft add rule inet ddos_guard input ip saddr @blocked4 drop");

        if (cfg.enable_amp_shield) {
            // shield set for amp sports
            run_cmd("nft list set inet ddos_guard amp_sports >/dev/null 2>&1 || nft add set inet ddos_guard amp_sports { type inet_service\\; }");
            // populate set (idempotent-ish: add element may fail if exists; ignore)
            for (uint16_t p : cfg.amp_sports) {
                run_cmd("nft add element inet ddos_guard amp_sports { " + std::to_string(p) + " } >/dev/null 2>&1");
            }
            run_cmd("nft list ruleset | grep -q \"udp sport @amp_sports drop\" || nft add rule inet ddos_guard input udp sport @amp_sports drop");
        }
    } else if (cfg.fw == FWBackend::IPTABLES) {
        run_cmd("iptables -nL DDOS_GUARD >/dev/null 2>&1 || iptables -N DDOS_GUARD");
        run_cmd("iptables -C INPUT -j DDOS_GUARD >/dev/null 2>&1 || iptables -I INPUT 1 -j DDOS_GUARD");
        // amp shield (simple)
        if (cfg.enable_amp_shield) {
            for (uint16_t p : cfg.amp_sports) {
                run_cmd("iptables -C DDOS_GUARD -p udp --sport " + std::to_string(p) + " -j DROP >/dev/null 2>&1 || "
                                                                                       "iptables -I DDOS_GUARD 1 -p udp --sport " + std::to_string(p) + " -j DROP");
            }
        }
    }
}

static void fw_block_ip(const Config& cfg, uint32_t ip_net, int seconds, const char* reason) {
    auto s = ip_to_str(ip_net);
    std::fprintf(stderr, "[BLOCK] %s for %ds (%s)\n", s.c_str(), seconds, reason);

    if (cfg.fw == FWBackend::NFT) {
        // timeout element
        run_cmd("nft add element inet ddos_guard blocked4 { " + s + " timeout " + std::to_string(seconds) + "s }");
    } else if (cfg.fw == FWBackend::IPTABLES) {
        // iptables has no timeout built-in; crude add (manual cleanup is needed in prod)
        run_cmd("iptables -C DDOS_GUARD -s " + s + " -j DROP >/dev/null 2>&1 || iptables -I DDOS_GUARD 1 -s " + s + " -j DROP");
    }
}

// ---------- Flow tracking for HTTP(80) and TLS(443) ----------
struct FlowKey {
    uint32_t src, dst;
    uint16_t sport, dport;
    bool operator==(const FlowKey& o) const {
        return src==o.src && dst==o.dst && sport==o.sport && dport==o.dport;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        size_t h=1469598103934665603ull;
        auto mix=[&](uint64_t v){ h^=v; h*=1099511628211ull; };
        mix(k.src); mix(k.dst);
        mix(((uint32_t)k.sport<<16)|k.dport);
        return h;
    }
};

struct FlowState {
    uint64_t start_sec=0;
    uint64_t last_sec=0;

    // HTTP header parsing
    bool hdr_done=false;
    std::string buf; // up to 8KB

    // TLS: count bytes to detect “stuck”
    uint64_t bytes_seen=0;
};

struct PerSrcSec {
    uint64_t last_sec=0;

    // UDP
    RateBucket udp_any;
    RateBucket amp;

    // TCP SYN
    uint64_t syn_to_web=0;

    // HTTP
    uint64_t http_req=0;
    uint64_t api_req=0;

    // TLS conns
    uint64_t tls_newconn=0;

    // open flows counters computed lazily
    uint64_t open_http_flows=0;
    uint64_t open_tls_flows=0;
    uint64_t tls_stuck_flows=0;
};

struct GlobalSec {
    RateBucket udp_any;
    RateBucket amp;
    uint64_t syn_to_web=0;
    uint64_t http_req=0;
    uint64_t tls_newconn=0;
};

struct State {
    Config cfg;
    uint64_t current_sec=0;

    std::unordered_map<uint32_t, PerSrcSec> per_src;
    GlobalSec g;

    std::unordered_map<FlowKey, FlowState, FlowKeyHash> flows;

    std::unordered_map<std::string, uint64_t> last_alert_sec;
};

// ---------- alerts ----------
static void alert_once(State& st, const std::string& key, const std::string& msg) {
    auto it = st.last_alert_sec.find(key);
    if (it != st.last_alert_sec.end() && it->second == st.current_sec) return;
    st.last_alert_sec[key] = st.current_sec;
    std::fprintf(stderr, "%s\n", msg.c_str());
}

// ---------- HTTP parse ----------
static bool parse_http_request_line(const std::string& hdrs, std::string& method, std::string& path) {
    auto eol = hdrs.find("\r\n");
    if (eol == std::string::npos) return false;
    auto line = hdrs.substr(0, eol);
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    auto sp2 = line.find(' ', sp1+1);
    if (sp2 == std::string::npos) return false;
    method = line.substr(0, sp1);
    path = line.substr(sp1+1, sp2-sp1-1);
    return true;
}

// ---------- per-src enforcement ----------
static void enforce_per_src(State& st, uint32_t src_ip) {
    auto& p = st.per_src[src_ip];

    // UDP flood
    if (p.udp_any.pkts > st.cfg.UDP_PPS_PER_SRC || p.udp_any.bytes > st.cfg.UDP_BPS_PER_SRC) {
        alert_once(st, "S_UDP_" + ip_to_str(src_ip),
                   "[ALERT] UDP Flood (src " + ip_to_str(src_ip) + "): PPS=" + std::to_string(p.udp_any.pkts) +
                       " Bps=" + std::to_string(p.udp_any.bytes));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "UDP_FLOOD");
        return;
    }

    // Amp/reflection
    if (p.amp.pkts > st.cfg.AMP_PPS_PER_SRC) {
        alert_once(st, "S_AMP_" + ip_to_str(src_ip),
                   "[ALERT] Reflection/Amp (src " + ip_to_str(src_ip) + "): PPS=" + std::to_string(p.amp.pkts));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "AMP_REFLECTION");
        return;
    }

    // SYN flood to web
    if (p.syn_to_web > st.cfg.SYN_PPS_PER_SRC) {
        alert_once(st, "S_SYN_" + ip_to_str(src_ip),
                   "[ALERT] SYN Flood (src " + ip_to_str(src_ip) + "): PPS=" + std::to_string(p.syn_to_web));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "SYN_FLOOD");
        return;
    }

    // HTTP flood
    if (p.http_req > st.cfg.HTTP_RPS_PER_SRC) {
        alert_once(st, "S_HTTP_" + ip_to_str(src_ip),
                   "[ALERT] HTTP Flood (src " + ip_to_str(src_ip) + "): RPS=" + std::to_string(p.http_req));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "HTTP_FLOOD");
        return;
    }
    if (p.api_req > st.cfg.API_RPS_PER_SRC) {
        alert_once(st, "S_API_" + ip_to_str(src_ip),
                   "[ALERT] API Flood (src " + ip_to_str(src_ip) + "): RPS=" + std::to_string(p.api_req));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "API_FLOOD");
        return;
    }

    // TLS new connections
    if (p.tls_newconn > st.cfg.TLS_NEWCONN_PER_SRC) {
        alert_once(st, "S_TLSNEW_" + ip_to_str(src_ip),
                   "[ALERT] HTTPS Flood suspected (src " + ip_to_str(src_ip) + "): newConnPPS=" + std::to_string(p.tls_newconn));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "TLS_NEWCONN_FLOOD");
        return;
    }

    // Slowloris / stuck TLS: too many open flows
    if (p.open_http_flows > st.cfg.OPEN_HTTP_FLOWS_PER_SRC) {
        alert_once(st, "S_OPENHTTP_" + ip_to_str(src_ip),
                   "[ALERT] Too many open HTTP flows (src " + ip_to_str(src_ip) + "): " + std::to_string(p.open_http_flows));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "SLOWLORIS_HTTP");
        return;
    }
    if (p.open_tls_flows > st.cfg.OPEN_TLS_FLOWS_PER_SRC && p.tls_stuck_flows > (p.open_tls_flows/2)) {
        alert_once(st, "S_OPENTLS_" + ip_to_str(src_ip),
                   "[ALERT] HTTPS Slowloris-like (src " + ip_to_str(src_ip) + "): open=" + std::to_string(p.open_tls_flows) +
                       " stuck=" + std::to_string(p.tls_stuck_flows));
        if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "SLOWLORIS_TLS");
        return;
    }
}

// ---------- per-second roll ----------
static void reset_per_src_sec(PerSrcSec& p) {
    reset_bucket(p.udp_any);
    reset_bucket(p.amp);
    p.syn_to_web=0;
    p.http_req=0;
    p.api_req=0;
    p.tls_newconn=0;
    p.open_http_flows=0;
    p.open_tls_flows=0;
    p.tls_stuck_flows=0;
}

static void roll_second(State& st, uint64_t sec) {
    if (st.current_sec == 0) {
        st.current_sec = sec;
        if (st.cfg.apply) fw_init_if_needed(st.cfg);
        return;
    }
    if (sec == st.current_sec) return;

    // глобальные алерты по прошлой секунде
    if (st.g.udp_any.pkts > st.cfg.UDP_PPS_GLOBAL || st.g.udp_any.bytes > st.cfg.UDP_BPS_GLOBAL) {
        alert_once(st, "G_UDP",
                   "[ALERT] UDP Flood (global): PPS=" + std::to_string(st.g.udp_any.pkts) +
                       " Bps=" + std::to_string(st.g.udp_any.bytes));
    }
    if (st.g.amp.pkts > st.cfg.AMP_PPS_GLOBAL) {
        alert_once(st, "G_AMP",
                   "[ALERT] Reflection/Amp (global): PPS=" + std::to_string(st.g.amp.pkts));
    }
    if (st.g.syn_to_web > st.cfg.SYN_PPS_GLOBAL) {
        alert_once(st, "G_SYN",
                   "[ALERT] SYN Flood (global): PPS=" + std::to_string(st.g.syn_to_web));
    }
    if (st.g.http_req > st.cfg.HTTP_RPS_GLOBAL) {
        alert_once(st, "G_HTTP",
                   "[ALERT] HTTP Flood (global): RPS=" + std::to_string(st.g.http_req));
    }
    if (st.g.tls_newconn > st.cfg.TLS_NEWCONN_GLOBAL) {
        alert_once(st, "G_TLS",
                   "[ALERT] HTTPS/TLS Flood (global): newConnPPS=" + std::to_string(st.g.tls_newconn));
    }

    // комбинированные алерты (таблица)
    if (st.g.udp_any.pkts > st.cfg.UDP_PPS_GLOBAL/2 && st.g.http_req > st.cfg.HTTP_RPS_GLOBAL/2) {
        alert_once(st, "C_UDP_HTTP",
                   "[COMBO] UDP Flood + HTTP Flood: need L3+L7 mitigation");
    }
    if (st.g.amp.pkts > st.cfg.AMP_PPS_GLOBAL/2 && st.g.syn_to_web > st.cfg.SYN_PPS_GLOBAL/2) {
        alert_once(st, "C_DNS_SYN",
                   "[COMBO] Reflection/Amp + SYN Flood: breaks network + firewall");
    }
    if (st.g.tls_newconn > st.cfg.TLS_NEWCONN_GLOBAL/2) {
        // slowloris over TLS смотрим через flows ниже (пер-src)
        alert_once(st, "C_TLS_SLOW_HINT",
                   "[COMBO] HTTPS Flood suspected; watch for stuck TLS conns (CPU+FD)");
    }
    if (st.g.amp.pkts > st.cfg.AMP_PPS_GLOBAL/2 && st.g.http_req > st.cfg.HTTP_RPS_GLOBAL/3) {
        alert_once(st, "C_REFL_API_HINT",
                   "[COMBO] Reflection + HTTP/API pressure: channel + DB risk");
    }

    // advance second
    st.current_sec = sec;
    reset_bucket(st.g.udp_any);
    reset_bucket(st.g.amp);
    st.g.syn_to_web=0;
    st.g.http_req=0;
    st.g.tls_newconn=0;

    // cleanup per-src (keep 60s)
    std::vector<uint32_t> dead;
    for (auto& kv : st.per_src) {
        if (kv.second.last_sec + 60 < st.current_sec) dead.push_back(kv.first);
        else reset_per_src_sec(kv.second);
    }
    for (auto ip : dead) st.per_src.erase(ip);

    // cleanup flows (keep 60s)
    std::vector<FlowKey> fdead;
    for (auto& kv : st.flows) {
        if (kv.second.last_sec + 60 < st.current_sec) fdead.push_back(kv.first);
    }
    for (auto& k : fdead) st.flows.erase(k);
}

// ---------- flow-based slowloris counters (computed each packet cheaply) ----------
static void update_open_flow_counters(State& st) {
    // Считаем open flows per-src по текущей таблице flows.
    // Это O(Nflows) — поэтому делаем редко: здесь для простоты вызываем раз в секунду при первом пакете секунды.
    // Чтобы не усложнять, вызовем, когда counters ещё нули (первая активность секунды).
    // (При очень большом Nflows лучше вынести в отдельный таймер.)
    std::unordered_map<uint32_t, std::pair<uint64_t,uint64_t>> tmp; // src -> (open_http, open_tls)
    std::unordered_map<uint32_t, uint64_t> tmp_stuck_tls;

    for (auto& kv : st.flows) {
        const FlowKey& fk = kv.first;
        FlowState& fs = kv.second;
        uint64_t age = (st.current_sec >= fs.start_sec) ? (st.current_sec - fs.start_sec) : 0;

        if (fk.dport == st.cfg.HTTP_PORT) {
            tmp[fk.src].first++;
        } else if (fk.dport == st.cfg.HTTPS_PORT) {
            tmp[fk.src].second++;
            if (age >= st.cfg.TLS_STUCK_AGE_SEC && fs.bytes_seen <= st.cfg.TLS_TINY_BYTES_MAX) {
                tmp_stuck_tls[fk.src]++;
            }
        }
    }
    for (auto& kv : tmp) {
        auto& p = st.per_src[kv.first];
        p.open_http_flows = kv.second.first;
        p.open_tls_flows  = kv.second.second;
    }
    for (auto& kv : tmp_stuck_tls) {
        auto& p = st.per_src[kv.first];
        p.tls_stuck_flows = kv.second;
    }
}

// ---------- packet handler ----------
static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    State& st = *reinterpret_cast<State*>(user);
    uint64_t sec = (uint64_t)h->ts.tv_sec;
    roll_second(st, sec);

    // first activity of second -> update open flow counters once
    // heuristic: if any per-src entry has open counters still 0 but flows exist, just recompute once
    static uint64_t last_open_update_sec = 0;
    if (st.current_sec != last_open_update_sec) {
        update_open_flow_counters(st);
        last_open_update_sec = st.current_sec;
    }

    if (h->caplen < sizeof(EthHdr)) return;
    const EthHdr* eth = reinterpret_cast<const EthHdr*>(bytes);
    if (ntohs(eth->type) != 0x0800) return; // IPv4 only

    const uint8_t* ip_ptr = bytes + sizeof(EthHdr);
    size_t ip_avail = h->caplen - sizeof(EthHdr);
    if (ip_avail < sizeof(IPv4Hdr)) return;

    const IPv4Hdr* ip = reinterpret_cast<const IPv4Hdr*>(ip_ptr);
    uint8_t version = (ip->ver_ihl >> 4) & 0x0F;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (version != 4 || ihl < 20 || ip_avail < ihl) return;

    uint32_t src_ip = ip->src;
    const uint8_t* l4 = ip_ptr + ihl;
    size_t l4_avail = ip_avail - ihl;

    auto& ps = st.per_src[src_ip];
    ps.last_sec = st.current_sec;

    // --- UDP (flood + reflection/amp) ---
    if (ip->proto == 17) {
        if (l4_avail < sizeof(UDPHdr)) return;
        const UDPHdr* udp = reinterpret_cast<const UDPHdr*>(l4);
        uint16_t sport = ntohs(udp->src_port);
        uint16_t dport = ntohs(udp->dst_port);
        uint16_t ulen  = ntohs(udp->len);
        if (ulen < 8) return;
        size_t payload_len = (size_t)ulen - 8;

        // count generic udp
        ps.udp_any.pkts++; ps.udp_any.bytes += h->len;
        st.g.udp_any.pkts++; st.g.udp_any.bytes += h->len;

        // reflection/amp pattern: sport in amp list + big payload
        if (st.cfg.amp_sports.count(sport) && payload_len >= st.cfg.MIN_AMP_PAYLOAD) {
            ps.amp.pkts++; ps.amp.bytes += h->len;
            st.g.amp.pkts++; st.g.amp.bytes += h->len;
        }

        enforce_per_src(st, src_ip);
        return;
    }

    // --- TCP (SYN flood + HTTP + Slowloris + TLS flood + TLS slow) ---
    if (ip->proto == 6) {
        if (l4_avail < sizeof(TCPHdr)) return;
        const TCPHdr* tcp = reinterpret_cast<const TCPHdr*>(l4);
        uint8_t off = (tcp->off_res >> 4) & 0x0F;
        size_t thl = (size_t)off * 4;
        if (thl < 20 || l4_avail < thl) return;

        uint16_t sport = ntohs(tcp->src_port);
        uint16_t dport = ntohs(tcp->dst_port);
        uint8_t flags  = tcp->flags;

        bool SYN = flags & 0x02;
        bool ACK = flags & 0x10;

        const uint8_t* payload = l4 + thl;
        size_t payload_len = l4_avail - thl;

        // SYN flood to web ports
        if (SYN && !ACK && (dport == st.cfg.HTTP_PORT || dport == st.cfg.HTTPS_PORT)) {
            ps.syn_to_web++;
            st.g.syn_to_web++;
            if (dport == st.cfg.HTTPS_PORT) {
                ps.tls_newconn++;
                st.g.tls_newconn++;
            }
            enforce_per_src(st, src_ip);
            return;
        }

        // Track flows for 80/443 (for slowloris-like)
        if (dport == st.cfg.HTTP_PORT || dport == st.cfg.HTTPS_PORT) {
            FlowKey fk{src_ip, ip->dst, sport, dport};
            auto& fs = st.flows[fk];
            if (fs.start_sec == 0) fs.start_sec = st.current_sec;
            fs.last_sec = st.current_sec;
            fs.bytes_seen += payload_len;

            // HTTP parsing for port 80 (plaintext only)
            if (dport == st.cfg.HTTP_PORT) {
                if (!fs.hdr_done && payload_len > 0) {
                    size_t cap = 8192;
                    size_t need = (fs.buf.size() < cap) ? (cap - fs.buf.size()) : 0;
                    size_t take = std::min(need, payload_len);
                    fs.buf.append(reinterpret_cast<const char*>(payload), take);

                    auto pos = fs.buf.find("\r\n\r\n");
                    if (pos != std::string::npos) {
                        fs.hdr_done = true;
                        std::string hdrs = fs.buf.substr(0, pos + 4);

                        std::string method, path;
                        if (parse_http_request_line(hdrs, method, path)) {
                            ps.http_req++;
                            st.g.http_req++;

                            if (is_api_path(path)) ps.api_req++;

                            enforce_per_src(st, src_ip);
                        }
                    } else {
                        // Slowloris: headers not done and old enough
                        uint64_t age = st.current_sec - fs.start_sec;
                        if (age >= st.cfg.SLOW_HDR_TIMEOUT_SEC) {
                            alert_once(st, "S_SLOWHDR_" + ip_to_str(src_ip),
                                       "[ALERT] Slowloris suspected (src " + ip_to_str(src_ip) + "): header not finished age=" + std::to_string(age) + "s");
                            if (st.cfg.apply) fw_block_ip(st.cfg, src_ip, st.cfg.block_seconds, "SLOWLORIS_HTTP");
                        }
                    }
                }
            } else {
                // TLS slowloris-like will be handled by open flow counters (bytes_seen small, age big)
                enforce_per_src(st, src_ip);
            }
        }

        return;
    }
}

// ---------- CLI helpers ----------
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
