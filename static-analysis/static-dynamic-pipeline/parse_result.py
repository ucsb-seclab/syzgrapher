import sys
import pickle
import os.path
import subprocess

class DynamicFuncPtrResolution:
    """ Class to parse and query the results of dynamic pointer resolution.

    This class parses the results of the dynamic pointer resolution and allows
    to query the results. If a cache file is given, the results are stored in
    the cache file and loaded from there if the cache file exists.

    Attributes:
        vmlinux (str): Path to the vmlinux file.
        overview_file (str): Path to the overview file (mapping between socket args/fds and fail/success).
        network_data_file (str): Path to the data file for the network stack (function pointers).
        fd_data_file (str): Path to the data file for general fds (function pointers).
        cache_file (str): Path to the cache file. If None, no cache is used.
        blobs (dict): Dictionary containing the parsed kernel structs with function pointers.
        overview (dict): Dictionary containing the overview of the results.
        family_max (int): Maximum family number.
        sock_max (int): Maximum socket type number.
        protocol_max (int): Maximum protocol number.
        p (subprocess.Popen): Subprocess running addr2line.
    """

    def __init__(self, network_data_file, fd_data_file, overview_file, vmlinux, cache_file=None):
        """ Initialize the class.

        Args:
            network_data_file (str): Path to the network stack data file (function pointers).
            fd_data_file (str): Path to the generic fd data file (function pointers).
            overview_file (str): Path to the overview file (mapping between socket args and fail/success).
            vmlinux (str): Path to the vmlinux file.
            cache_file (str): Path to the cache file. If None, no cache is used.

        This only initializes the fields. To actually parse the data, call parse().
        """
        self.vmlinux = vmlinux
        self.overview_file = overview_file
        self.network_data_file = network_data_file
        self.fd_data_file = fd_data_file
        self.cache_file = cache_file
        self.p = self._startAddr2line()

    def parse(self):
        """ Parse the data files.

        This function parses the data files and stores the results in the class.
        """
        if self.cache_file is not None and os.path.exists(self.cache_file):
            with open(self.cache_file, 'rb') as f:
                (self.blobs, self.overview) = pickle.load(f)
        else:
            with open(self.network_data_file, 'rb') as f:
                network_data = f.read()

            with open(self.fd_data_file, 'rb') as f:
                fd_data = f.read()

            with open(self.overview_file, 'r') as f:
                lines = f.readlines()

            self._parse_lines(lines)

            self._parse_nw_blobs(network_data)

            self._parse_fd_blobs(fd_data)

    def _parse_lines(self, lines):
        """ Parse the overview file. """

        family = {}
        family_max, sock_max, protocol_max = 0, 0, 0
        for line in lines:
            sp = line.split("|")
            if len(sp) == 1:
                # this is a fd
                sp = line.split(" ")
                if sp[0] not in family:
                    family[sp[0]] = {}
                family[sp[0]] = sp[1]
            else:
                # this is a socket
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
        self.overview = family
        self.family_max = family_max
        self.sock_max = sock_max
        self.protocol_max = protocol_max

    def _parse_fd_blobs(self, data):
        """ Parse all function pointers. """

        while len(data) > 0:
            # read string bytewise until the nullbyte
            i = 0
            while data[i] != 0:
                i += 1
            file_path = data[:i].decode('utf-8')
            data = data[i+1:]

            # read fops size
            fops_size = int.from_bytes(data[:4], byteorder='little')
            data = data[4:]

            # read fops
            fops = data[:fops_size]
            data = data[fops_size:]

            if file_path not in self.blobs:
                self.blobs[file_path] = {}
            self.blobs[file_path]["file_operations"] = fops

            # read magic
            magic = int.from_bytes(data[:4], byteorder='little')
            if magic != 0xbeefdead:
                print("Error: magic mismatch", magic)
                exit(1)
            data = data[4:]

    def _parse_nw_blobs(self, data):
        """ Parse all function pointers. """

        blobs = {}
        for i in range(self.family_max+1):
            for j in range(self.sock_max+1):
                for k in range(self.protocol_max+1):
                    if self.overview[i][j][k] == "failed":
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
                    fops_size = int.from_bytes(data[:4], byteorder='little')
                    data = data[4:]

                    blobs[f][s][p]["proto_ops"] = data[:ops_size]
                    data = data[ops_size:]
                    blobs[f][s][p]["proto"] = data[:prot_size]
                    data = data[prot_size:]
                    blobs[f][s][p]["sock"] = data[:sock_size]
                    data = data[sock_size:]
                    blobs[f][s][p]["file_operations"] = data[:fops_size]
                    data = data[fops_size:]

                    magic = int.from_bytes(data[:4], byteorder='little')
                    if magic != 0xbeefdead:
                        print("Error: magic mismatch", magic)
                        exit(1)
                    data = data[4:]
        self.blobs = blobs

    def _startAddr2line(self):
        """ Start addr2line in a subprocess. """

        p = subprocess.Popen(["addr2line", "-f", "-e", self.vmlinux], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        return p

    def executeQuery(self, query):
        """ Execute a query on the dynamically extracted data. """

        if query.file_path is not None:
            if not isinstance(query.file_path, list):
                query.file_path = [query.file_path]
            functions = []
            for file_path in query.file_path:
                if file_path not in self.blobs:
                    continue
                if query.struct not in self.blobs[file_path]:
                    continue
                blob = self.blobs[file_path][query.struct]
                if query.offset + 8 > len(blob):
                    continue
                print("Looking up", hex(int.from_bytes(blob[query.offset:query.offset+8], byteorder='little', signed=False)))
                fkt = self.addr2line(blob[query.offset:query.offset+8])
                if fkt:
                    functions.append(fkt)
            return functions

        fams = []
        if query.family == -1:
            fams = list(self.overview.keys())
        else:
            fams = [query.family]
        socks = []
        if query.socket == -1:
            socks = list(self.overview[fams[0]].keys())
        else:
            socks = [query.socket]
        prots = []
        if query.protocol == -1:
            prots = list(self.overview[fams[0]][socks[0]].keys())
        else:
            prots = [query.protocol]
        functions = []
        for fam in fams:
            for sock in socks:
                for prot in prots:
                    if (fam not in self.overview
                        or sock not in self.overview[fam]
                        or prot not in self.overview[fam][sock]):
                        continue
                    if self.overview[fam][sock][prot] == "failed":
                        continue
                    if (fam not in self.blobs
                        or sock not in self.blobs[fam]
                        or prot not in self.blobs[fam][sock]):
                        continue
                    blob = self.blobs[fam][sock][prot][query.struct]
                    if query.offset + 8 > len(blob):
                        continue
                    fkt = self.addr2line(blob[query.offset:query.offset+8])
                    if fkt:
                        functions.append(fkt)
        return list(set(functions))

    def addr2line(self, addr):
        """ Use addr2line to find the function name for an address. """

        addr = int.from_bytes(addr, byteorder='little', signed=False)
        if addr == 0:
            return
        #print("Looking up", hex(addr))
        self.p.stdin.write(hex(addr).encode('utf-8'))
        self.p.stdin.write(b'\n')
        self.p.stdin.flush()
        fkt = self.p.stdout.readline().decode('utf-8').strip()
        self.p.stdout.readline()
        return fkt

    def shutdown(self):
        """ Shutdown addr2line. """

        self.p.stdin.close()
        self.p.wait()
        if self.cache_file is not None:
            with open(self.cache_file, 'wb') as f:
                pickle.dump((self.blobs, self.overview), f)

class Query:
    def __init__(self, family, socket, protocol, struct, offset, file_path):
        self.file_path = file_path
        self.family = family
        self.socket = socket
        self.protocol = protocol
        self.struct = struct
        self.offset = offset

class LookupResult:
    def __init__(self, query, functions):
        self.query = query
        self.functions = functions
