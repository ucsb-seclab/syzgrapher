import sys
import pickle
import os.path
import subprocess

def parse_lines(lines):
    family = {}
    family_max, sock_max, protocol_max = 0, 0, 0
    for line in lines:
        sp = line.split("|")
        f = int(sp[0].strip())
        s = int(sp[1].strip())
        sp = sp[2].strip().split(" ")
        p = int(sp[0])
        if f not in family:
            family[f] = {}
        if s not in family[f]:
            family[f][s] = {}
        family[f][s][p] = sp[1]
        family_max = max(family_max, f)
        sock_max = max(sock_max, s)
        protocol_max = max(protocol_max, p)
    return family, family_max, sock_max, protocol_max

def parse_blobs(data, family_max, sock_max, protocol_max, overview):
    blobs = {}
    for i in range(family_max+1):
        for j in range(sock_max+1):
            for k in range(protocol_max+1):
                if overview[i][j][k] == "failed":
                    continue
                #print("Parsing family", i, "socket", j, "protocol", k)
                f = int.from_bytes(data[:4], byteorder='little')
                if f != i:
                    print("Error: family mismatch", f, i)
                    print(''.join(format(x, '02x') for x in data[:4]))
                    print(''.join(format(x, '02x') for x in data[4:8]))
                    print(''.join(format(x, '02x') for x in data[8:12]))
                    exit(1)
                data = data[4:]
                s = int.from_bytes(data[:4], byteorder='little')
                if s != j:
                    print("Error: socket mismatch", s, j)
                    exit(1)
                data = data[4:]
                p = int.from_bytes(data[:4], byteorder='little')
                if p != k:
                    print("Error: protocol mismatch", p, k)
                    exit(1)
                data = data[4:]
                if f not in blobs:
                    blobs[f] = {}
                if s not in blobs[f]:
                    blobs[f][s] = {}
                if p not in blobs[f][s]:
                    blobs[f][s][p] = {}
                ops_size = int.from_bytes(data[:4], byteorder='little')
                data = data[4:]
                prot_size = int.from_bytes(data[:4], byteorder='little')
                data = data[4:]
                sock_size = int.from_bytes(data[:4], byteorder='little')
                data = data[4:]

                blobs[f][s][p]["ops"] = data[:ops_size]
                data = data[ops_size:]
                blobs[f][s][p]["prot"] = data[:prot_size]
                data = data[prot_size:]
                blobs[f][s][p]["sock"] = data[:sock_size]
                data = data[sock_size:]

                magic = int.from_bytes(data[:4], byteorder='little')
                if magic != 0xbeefdead:
                    print("Error: magic mismatch", magic)
                    exit(1)
                data = data[4:]
    return blobs

class Query:
    def __init__(self, family, socket, protocol, struct, offset):
        self.family = family
        self.socket = socket
        self.protocol = protocol
        self.struct = struct
        self.offset = offset

def executeQuery(overview, blobs, query, p):
    fams = []
    if query.family == -1:
        fams = list(overview.keys())
    else:
        fams = [query.family]
    socks = []
    if query.socket == -1:
        socks = list(overview[fams[0]].keys())
    else:
        socks = [query.socket]
    prots = []
    if query.protocol == -1:
        prots = list(overview[fams[0]][socks[0]].keys())
    else:
        prots = [query.protocol]
    functions = []
    for fam in fams:
        for sock in socks:
            for prot in prots:
                if (fam not in overview
                    or sock not in overview[fam]
                    or prot not in overview[fam][sock]):
                    continue
                if overview[fam][sock][prot] == "failed":
                    continue
                if (fam not in blobs
                    or sock not in blobs[fam]
                    or prot not in blobs[fam][sock]):
                    continue
                blob = blobs[fam][sock][prot][query.struct]
                fkt = addr2line(blob[query.offset:query.offset+8], p)
                if fkt:
                    functions.append(fkt)
    return list(set(functions))

def interactiveQuery(overview, blobs):
    while True:
        print("Enter family, socket, protocol, operation")
        print("Enter -1 to exit")
        f = int(input())
        if f == -1:
            break
        s = int(input())
        p = int(input())
        o = int(input())
        if f not in overview or s not in overview[f] or p not in overview[f][s]:
            print("Error: overview not found")
            continue
        if overview[f][s][p] == "failed":
            print("This socket is not supported")
            continue
        if f not in blobs or s not in blobs[f] or p not in blobs[f][s]:
            print("Error: blob not found")
            continue
        blob = blobs[f][s][p]
        if o == 0:
            print(blob["ops"])
        elif o == 1:
            print(blob["prot"])
        elif o == 2:
            print(blob["sock"])
        else:
            print("Error: operation not found")
            continue

def startAddr2line(vmlinux):
    p = subprocess.Popen(["addr2line", "-f", "-e", vmlinux], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return p

def addr2line(addr, p):
    addr = int.from_bytes(addr, byteorder='little', signed=False)
    if addr == 0:
        return
    #print("Looking up", hex(addr))
    p.stdin.write(hex(addr).encode('utf-8'))
    p.stdin.write(b'\n')
    p.stdin.flush()
    fkt = p.stdout.readline().decode('utf-8').strip()
    p.stdout.readline()
    return fkt

def main():
    if len(sys.argv) < 4:
        print('Usage: python parse_result.py <data_file> <overview_file> <vmlinux> [<cache>]')
        exit(1)

    if len(sys.argv) == 5 and os.path.exists(sys.argv[4]):
        cache_file = sys.argv[4]
        with open(cache_file, 'rb') as f:
            (blobs, overview) = pickle.load(f)
    else:
        data_file = sys.argv[1]
        overview_file = sys.argv[2]

        with open(data_file, 'rb') as f:
            data = f.read()

        with open(overview_file, 'r') as f:
            lines = f.readlines()

        overview, family_max, sock_max, protocol_max  = parse_lines(lines)

        blobs = parse_blobs(data, family_max, sock_max, protocol_max, overview)

    p = startAddr2line(sys.argv[3])


    #interactiveQuery(overview, blobs)

    q = Query(-1, -1, -0, "ops", 120)
    print(executeQuery(overview, blobs, q, p))

    if len(sys.argv) == 5:
        cache_file = sys.argv[4]
        with open(cache_file, 'wb') as f:
            pickle.dump((blobs, overview), f)

if __name__ == '__main__':
    main()
