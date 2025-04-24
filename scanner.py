import ipaddress
import redis
import time
import json
import subprocess
import os

conn = redis.Redis(host='localhost', port=6379, db=0)

MAC_ADDR = "80:41:26:1e:d7:11"
INT_NAME = "enp179s0f1"
def scan(ips, task_type):
    # write ips to a tmp file
    target_file = "tmp_targets.txt"
    result_file = "tmp_results.txt"
    with open(target_file, 'w') as f:
        for ip in ips:
            f.write(f"{ip}\n")
    if task_type == "host":
        # run masscan
        command = 'masscan --ping --router-mac-ipv6 {} --interface {} -iL {} --max-rate=10000 -oL {}'.format(MAC_ADDR, INT_NAME, target_file, result_file)
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while p.poll() == None:
            time.sleep(0.1)
        active_addrs = set()
        if p.poll() == 0:  # Changed 'is' to '==' for comparison
            # Modified output parsing for masscan format
            for line in open(result_file):
                if line.startswith('#'):  # Skip comment lines
                    continue
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 4:  # masscan output format: <state> <protocol> <port> <ip>
                        addr = ipaddress.ip_address(parts[3]).exploded
                        active_addrs.add(addr)
        # save active ips to redis
        for ip in ips:
            if ip in active_addrs:
                conn.hset(task_type, ip, 1)
            else:
                conn.hset(task_type, ip, 0)
    elif task_type == "port":
        # run masscan
        command = 'masscan -p22,80,443 --router-mac-ipv6 {} --interface {} -iL {} --max-rate=10000 -oL {}'.format(MAC_ADDR, INT_NAME, target_file, result_file)
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while p.poll() == None:
            time.sleep(1)
        hosts = {}
        if p.poll() == 0:
            for ip in ips:
                # default fingerprints
                hosts[ip] = {'tcp22': '-', 'tcp80': '-', 'tcp443': '-'}
            with open(result_file, 'r') as output_file:
                for line in output_file:
                    if line.startswith('#') or not line.strip():  # Skip comment lines
                        continue
                    parts = line.strip().split()
                    if len(parts) >= 4:  # masscan output format: <state> <protocol> <port> <ip>
                        port = parts[1]+parts[2]
                        addr = ipaddress.ip_address(parts[3]).exploded
                        if addr in hosts:
                            # update fingerprints
                            hosts[addr][port] = '+'            
            for ip in hosts:
                fp = hosts[ip]['tcp22'] + hosts[ip]['tcp80'] + hosts[ip]['tcp443']
                conn.hset(task_type, ip, fp)
    elif task_type == "tcp22":
        # run ssh-keyscan
        # use this command: cat targets.txt | shuf | xargs -n 1 -P 200 ssh-keyscan  >> results.txt
        command = 'cat {} | shuf | xargs -I {{}} -P 200 sh -c \'timeout 4 ssh-keyscan {{}} 2>/dev/null\' > {}'.format(target_file, result_file)
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while p.poll() == None:
            time.sleep(1)
        hosts = {}
        for ip in ips:
            hosts[ip] = {'ecdsa-sha2-nistp256': '', 'ssh-rsa': '', 'ssh-ed25519': ''}
        res = p.poll()
        if res == 0 or res == 123:
            with open(result_file, 'r') as output_file:
                # ssh banner format (from ssh-keyscan):
                # 2a12:a343:6ea5:45b1:e4e2:c983:7955:47c2 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYT
                # 2a12:a343:6ea5:45b1:e4e2:c983:7955:47c2 ssh-rsa AAAAE2VjZHNhLXNoYT
                # 2a12:a343:6ea5:45b1:e4e2:c983:7955:47c2 ssh-ed25519 AAAAE2VjZHNhLXNoYT
                for line in output_file:
                    if line.startswith('#') or not line.strip():  # Skip comment lines
                        continue
                    parts = line.strip().split()
                    if len(parts) >= 3: 
                        addr = ipaddress.ip_address(parts[0]).exploded
                        ssh_key_type = parts[1]
                        ssh_key_value = parts[2]
                        if ssh_key_type in ['ecdsa-sha2-nistp256', 'ssh-rsa', 'ssh-ed25519']:
                            hosts[addr][ssh_key_type] = ssh_key_value
        for ip in hosts:
            fps = json.dumps(hosts[ip])
            conn.hset(task_type, ip, fps)                  

