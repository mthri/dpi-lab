import time
import random
from typing import TypeAlias
import scapy.all as scapy
from netfilterqueue import NetfilterQueue, Packet
from ndpi import NDPI, NDPIFlow, ffi


FlowKey: TypeAlias = tuple[tuple[str, str], tuple[int, int], int]
NFQUEUE_NUMBER = 3


# ------- Rule Area ------- #
class BaseRule:
    def apply(self, packet: scapy.IP, flow: 'Flow', ctx: 'PolicyContext') -> bool | None:
        """
        Apply the rule logic.
        Returns: True to accept, False to drop, None to continue.
        """
        raise NotImplementedError


class TrustedSrcRule(BaseRule):
    def apply(self, packet: scapy.IP, flow: 'Flow', ctx: 'PolicyContext') -> bool | None:
        if packet.src in ctx.trusted_ips:
            return True
        return None


class SNIFilterRule(BaseRule):
    def apply(self, packet: scapy.IP, flow: 'Flow', ctx: 'PolicyContext') -> bool | None:
        if not packet.haslayer(scapy.TCP):
            return None

        packet_time_ms = int(time.time() * 1000)
        flow.last_seen = packet_time_ms

        # Check if this flow was already flagged
        if flow.is_blocked:
            print(f'[DROP] SNI Filter: {packet.src}')
            return False

        try:
            ctx.ndpi_manager.process_packet(
                flow.ndpiflow,
                bytes(packet),
                packet_time_ms,
                ffi.NULL
            )

            if flow.ndpiflow.C.host_server_name != ffi.NULL:
                hostname = ffi.string(flow.ndpiflow.C.host_server_name).decode('utf-8', errors='ignore')
                if hostname in ctx.blocked_domains:
                    print(f'[DROP] SNI Filter: {packet.src} -> {hostname}')
                    flow.is_blocked = True
                    return False
            
        except Exception as e:
            print(e)
        
        return None


class IcmpProbabilisticDropRule(BaseRule):
    def apply(self, packet: scapy.IP, flow: 'Flow', ctx: 'PolicyContext') -> bool | None:
        if packet.haslayer(scapy.ICMP) and packet.dst in ctx.blocked_dst_ips:
            # Randomly drops 70% of ICMP packets to create disruption without full blocking.
            if random.random() < 0.7:
                print(f'[DROP] ICMP Filter: {packet.src} -> {packet.dst}')
                return False
        return None
# ------------------------- #


class Flow:
    def __init__(self) -> None:
        self.ndpiflow = NDPIFlow()
        self.last_seen = int(time.time() * 1000)
        self.is_blocked = False


class PolicyContext:
    def __init__(self) -> None:
        self.trusted_ips: set[str] = {'192.168.1.100', }
        self.blocked_dst_ips: set[str] = {'8.8.8.8', }
        self.blocked_domains: set[str] = {'google.com', }
        self.ndpi_manager = NDPI()
        self.flow_table: dict[FlowKey, Flow] = {}

    def get_flow_key(self, pkt: scapy.IP) -> FlowKey | None:
        if not pkt.haslayer(scapy.IP):
            return None
        
        src, dst = (pkt.src, pkt.dst) if pkt.src < pkt.dst else (pkt.dst, pkt.src)
        sport = getattr(pkt, 'sport', 0)
        dport = getattr(pkt, 'dport', 0)
        p1, p2 = (sport, dport) if sport < dport else (dport, sport)
        
        return ((src, dst), (p1, p2), pkt.proto)
    
    def cleanup_old_flows(self) -> None:
        current_time = int(time.time() * 1000)
        timeout = 10 * 60 * 1000  # 10 minutes in milliseconds
        
        # Collect keys to remove to avoid modifying dict while iterating
        keys_to_remove = [key for key, flow in self.flow_table.items()
                          if current_time - flow.last_seen > timeout]
        
        for key in keys_to_remove:
            del self.flow_table[key]


class PolicyEngine:
    def __init__(self, rules: list[BaseRule]) -> None:
        self.rules = rules

    def process(self, packet: scapy.IP, ctx: PolicyContext) -> bool:
        key = ctx.get_flow_key(packet)
        if key is None:
            return True

        flow = ctx.flow_table.setdefault(key, Flow())

        for rule in self.rules:
            result = rule.apply(packet, flow, ctx)
            if result is not None:
                return result
        return True


def nfqueue_callback(pkt: Packet) -> None:
    try:
        scapy_pkt = scapy.IP(pkt.get_payload())
        if engine.process(scapy_pkt, ctx):
            pkt.accept()
        else:
            pkt.drop()
    except Exception as e:
        print(f'[ERROR] Callback: {e}')
        pkt.accept()

if __name__ == '__main__':
    ctx = PolicyContext()
    engine = PolicyEngine([
        TrustedSrcRule(),
        SNIFilterRule(),
        IcmpProbabilisticDropRule()
    ])

    nfqueue = NetfilterQueue()
    nfqueue.bind(NFQUEUE_NUMBER, nfqueue_callback)

    print(f'[*] DPI Engine running on NFQUEUE {NFQUEUE_NUMBER}...')
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('\n[*] Shutting down...')
    finally:
        nfqueue.unbind()
