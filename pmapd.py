import math
import random
import redis
import json

from scanner import scan

conn_results = redis.Redis(host='localhost', port=6379, db=0)

MAX_PLEN = 28
MIN_PLEN = 8

aliased_prefixes = {}
nonaliased_prefixes = {}

def add_nonaliased_prefix(prefix, reason, passive=True):
    if passive:
        # expand non aliased prefix for passive detect
        nonaliased_prefixes[prefix] = reason
        print(f"add nonaliased: {prefix[:p]} {reason}")
        expands = 0
        for p in range(len(prefix)+1, MIN_PLEN-1, -1):
            if prefix[:p] not in nonaliased_prefixes:
                nonaliased_prefixes[prefix[:p]] = reason
                expands += 1
        if expands > 0:
            print(f"expand {expands} nonaliased prefixes")
    else:
        # do not expand non aliased prefix for active detect
        if prefix not in nonaliased_prefixes:
            nonaliased_prefixes[prefix] = reason
            print(f"add nonaliased: {prefix} {reason}")


def add_aliased_prefix(prefix, reason):
    if prefix not in aliased_prefixes:
        aliased_prefixes[prefix] = reason
        print(f"add aliased: {prefix} {reason}")

def is_aliased(addr):
    addr = addr.replace(':', '')
    for plen in range(MIN_PLEN, MAX_PLEN+1):
        prefix = addr[:plen]
        if prefix in aliased_prefixes:
            return True
    return False

def is_aliased_offline(addr):
    addr = addr.replace(':', '')
    for plen in range(MIN_PLEN, MAX_PLEN+1):
        prefix = addr[:plen]
        if prefix in aliased_prefixes:
            return True, prefix
    return False, None

def filter_online(targets):
    addr_set = set()
    for addr in targets:
        # skip aliased prefix
        if is_aliased(addr):
            continue
        addr_set.add(addr)
    return addr_set

def filter_offline(alives):
    res = set()
    aliased_prefixes_matched = set()
    for addr in alives:
        aliased, prefix = is_aliased_offline(addr)
        if aliased:
            if prefix not in aliased_prefixes_matched:
                # keep only one address for each matched prefix
                aliased_prefixes_matched.add(prefix)
                res.add(addr)
        else:
            res.add(addr)
    return res, aliased_prefixes_matched

def print_aliased():
    for prefix in aliased_prefixes:
        print(f"aliased: {prefix} {aliased_prefixes[prefix]}")
    for prefix in nonaliased_prefixes:
        print(f"nonaliased: {prefix} {nonaliased_prefixes[prefix]}")
         
prefixes = {}
    
def update_prefixes(ips):
    new_prefixes = set()
    for ip in ips:
        host_fp = conn_results.hget('host', ip)
        # print(f"ip: {ip}, host_fp: {host_fp}")
        # skip invalid host
        if host_fp is None or host_fp == b'':
            continue
        
        port_fp = None
        ssh_fp = None
        # if resp, fetch port info
        if host_fp == b'1':
            host_fp = 1
            port_fp = conn_results.hget('port', ip)
            # convert '' to None
            if port_fp == b'':
                port_fp = None
            if port_fp is not None:
                # if port open, fetch app info
                if port_fp[0] == 43:
                    ssh_fp = conn_results.hget('tcp22', ip)
                    if ssh_fp == b'':
                        ssh_fp = None
                    if ssh_fp is not None:
                        ssh_fp = json.loads(ssh_fp)
        else:
            host_fp = 0
        addr = ip.replace(':', '')
        for plen in range(MAX_PLEN, MIN_PLEN-1, -1):
            prefix = addr[:plen]
            # skip nonaliased prefix
            if prefix in nonaliased_prefixes:
                continue
            # skip aliased prefix
            # prefix = 20010001
            # if 2001 is aliased, then 20010001 is aliased too
            aliased_flag = False
            for j in range(plen, MIN_PLEN-1, -1):
                if prefix[:j] in aliased_prefixes:
                    aliased_flag = True
                    break
            if aliased_flag:
                continue
            
            new_prefixes.add(prefix)
            # init
            if prefix not in prefixes:
                # prefixes[prefix] = {
                #     'host': {
                #         b'0': 0,
                #         b'1': 0
                #     },
                #     'port': {},
                #     'ssh-rsa': {},
                #     'ssh-ed25519': {},
                #     'ecdsa-sha2-nistp256': {},
                # }
                # save memory
                prefixes[prefix] = [0,0, {}, None, None, None]
            # update host, index 0,1
            prefixes[prefix][host_fp] += 1
            # update port, index 2
            if port_fp is not None:
                if prefixes[prefix][2] is None:
                    prefixes[prefix][2] = {}
                if port_fp not in prefixes[prefix][2]:
                    prefixes[prefix][2][port_fp] = 1
                else:
                    prefixes[prefix][2][port_fp] += 1
            # update ssh, index 3,4,5
            if ssh_fp is not None:
                ssh_index = 3
                for t in ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256']:
                    if ssh_fp[t] != '':
                        if prefixes[prefix][ssh_index] is None:
                            prefixes[prefix][ssh_index] = {}
                        # save memory
                        short_key = ssh_fp[t][:5]
                        if short_key not in prefixes[prefix][ssh_index]:
                            prefixes[prefix][ssh_index][short_key] = 1
                        else:
                            prefixes[prefix][ssh_index][short_key] += 1
                    ssh_index += 1
    return new_prefixes

def passive_detect(new_prefixes):
    uncertain_prefixes = set()
    for prefix in new_prefixes:
        # calc aliased prefix
        certainFlag = None
        for ssh_index in range(3, 6):
            if prefixes[prefix][ssh_index] is not None and len(prefixes[prefix][ssh_index]) > 1:
                certainFlag = True
                add_nonaliased_prefix(prefix, "ssh")
                break
        if certainFlag == True:
            continue
        
        resp_cnt = prefixes[prefix][1]
        unresp_cnt = prefixes[prefix][0]
        total_cnt = resp_cnt + unresp_cnt
        if total_cnt < 100:
            # sparse prefix
            continue
        
        LOSS_RATE = 0.05
        Z_THRESHOLD = -5
        E_resp_cnt = total_cnt * (1-LOSS_RATE)
        V_resp_cnt = E_resp_cnt * LOSS_RATE
        Z = (resp_cnt - E_resp_cnt) / math.sqrt(V_resp_cnt)
        if Z < Z_THRESHOLD:
            add_nonaliased_prefix(prefix, "host")
            continue      
        # using port info
        fp_all = list(b'---')
        for fp in prefixes[prefix][2]:
            if fp[0] == 43:
                fp_all[0] = 43
            if fp[1] == 43:
                fp_all[1] = 43
                if fp[2] == 43:
                    fp_all[2] = 43
        # find fp_all
        fp_all = bytes(fp_all)
        open_ports = fp_all.count(43)
        if open_ports > 0:
            fp_all_p = pow((1-LOSS_RATE), open_ports)
            if fp_all in prefixes[prefix][2]:
                fp_all_cnt = float(prefixes[prefix][2][fp_all])
            else:
                fp_all_cnt = 0.0
            E_fp_all = resp_cnt * fp_all_p
            V_fp_all = E_fp_all * (1-fp_all_p)
            Z = (fp_all_cnt - E_fp_all) / math.sqrt(V_fp_all)
            if Z < Z_THRESHOLD:
                add_nonaliased_prefix(prefix, "port")
                continue
        uncertain_prefixes.add(prefix)
    # filter non-aliased prefix
    tmp = set()
    for prefix in uncertain_prefixes:
        if prefix in nonaliased_prefixes:
            continue
        tmp.add(prefix)
    return tmp

def active_detect(uncertain_prefixes):
    cnt = 0
    for plen in range(MIN_PLEN, MAX_PLEN+1):
        tmp_prefixes = set()
        for prefix in uncertain_prefixes:
            if len(prefix) == plen:
                for j in range(MIN_PLEN, plen):
                    if prefix[:j] in aliased_prefixes:
                        break
                else:
                    tmp_prefixes.add(prefix)
        if len(tmp_prefixes) > 0:
            cnt += active_detect_real(tmp_prefixes)
    return cnt
        
NIBBLE_VALUES = '0123456789abcdef'
def active_detect_real(uncertain_prefixes):
    rnd_ips = set()
    prefixes_ips = {}
    for prefix in uncertain_prefixes:
        prefixes_ips[prefix] = set()
        # select 3 subnets from SUBNETS
        subnets = random.sample(NIBBLE_VALUES, 3)
        remain_nibbles = 31-len(prefix)
        
        for subnet in subnets:
            rnd_ip = prefix + subnet
            for i in range(remain_nibbles):
                rnd_ip += random.choice(NIBBLE_VALUES)
            rnd_ipstr = ''
            for i in range(8):
                rnd_ipstr += rnd_ip[i*4:(i+1)*4] + ':'
            #print(rnd_ipstr[:-1])
            rnd_ips.add(rnd_ipstr[:-1])
            prefixes_ips[prefix].add(rnd_ipstr[:-1])
    
    scan(rnd_ips, "host")
    
    # scan the unresponsive addr another time
    unresp_ips = set()
    for ip in rnd_ips:
        if conn_results.hget('host', ip) == b'0':
            unresp_ips.add(ip)
    scan(unresp_ips, "host")
    
    # scan the unresponsive addr again
    unresp_ips2 = set()
    for ip in unresp_ips:
        if conn_results.hget('host', ip) == b'0':
            unresp_ips2.add(ip)
    scan(unresp_ips2, "host")
    
    for prefix in prefixes_ips:
        plen = len(prefix)
        cnt = 0
        for ip in prefixes_ips[prefix]:
            if conn_results.hget('host', ip) == b'1':
                cnt += 1
        if (plen > 96 and cnt >= 3) or (plen <= 96 and cnt >= 2):
            add_aliased_prefix(prefix, "active")
        else:
            add_nonaliased_prefix(prefix, "active", passive=False)
    # return overhead of active detect
    return len(rnd_ips)+len(unresp_ips)+len(unresp_ips2)
    
def alias_detect(ips):
    new_prefixes = update_prefixes(ips)
    print(f"prefixes: {len(new_prefixes)}")
    uncertain_prefixes = passive_detect(new_prefixes)
    print(f"uncertain: {len(uncertain_prefixes)}")
    pkts = active_detect(uncertain_prefixes)
    print(f"overhead: {pkts}")
    return pkts
