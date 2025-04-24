import sys
import redis

from scanner import scan
from pmapd import alias_detect, print_aliased, filter_online, filter_offline

conn = redis.Redis(host='localhost', port=6379, db=0)

def generate_target(i):
    ips = open(f"tga2/rnd{i}_targets10k.txt", 'r').readlines()
    addr_set = set()
    for ip in ips:
        addr_set.add(ip.strip())
    return addr_set

def scan_targets(addr_set):
    # host scan
    scan(addr_set, 'host')
    alive_ips = set()
    for ip in addr_set: 
        status = conn.hget('host', ip)
        if status == b'1':
            alive_ips.add(ip)

    # port scan
    # ExecScan(alive_ips, "port")
    # tcp22_ips = set()
    # for ip in alive_ips:
    #     port_fp = conn.hget('port', f"{ip}")
    #     if port_fp[0] == 43:
    #         tcp22_ips.add(ip)
    # print(f"Found {len(tcp22_ips)} tcp22 ips")

    # service scan
    # ExecScan(tcp22_ips, "tcp22")
    return alive_ips
    
if __name__ == '__main__':
    alives = set()
    for i in range(6):
        # simulate target generation algorithm (TGA)
        # use any TGA to generate real targets
        targets = generate_target(i)
        print(f"Round {i}: Generated {len(targets)} targets")
        
        # online filter
        addr_set = filter_online(targets)
        print(f"Round {i}: Filtered {len(targets) - len(addr_set)} aliased from targets")
        
        # scan targets
        rnd_alives = scan_targets(addr_set)
        alives.update(rnd_alives)
        print(f"Round {i}: Found {len(rnd_alives)} alive ips")
        
        # aliased detect
        alias_detect(addr_set)
    
    print_aliased()
    
    # offline filter
    dealiased, prefixes = filter_offline(alives)
    print(f"Found {len(dealiased)} dealiased ips")
    print(f"Found {len(prefixes)} aliased prefixes")