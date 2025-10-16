import sys
import json
import pickle
import os.path
import subprocess
from collections import defaultdict
import matplotlib as plt

from parse_result import DynamicFuncPtrResolution, Query, LookupResult
from codeql_interf import QueryBuilder, CodeQLAPI
TESTING=True
DEBUG=False

CMD_NR_MASK = 0x000000ff
CMD_TYPE_MASK = 0x0000ff00
CMD_SIZE_MASK = 0x3fff0000
CMD_DIR_MASK = 0xc0000000

CMD_TYPE_SHIFT = 8
CMD_SIZE_SHIFT = 16
CMD_DIR_SHIFT = 30

def cmd_to_str(cmd):
    cmd_nr = cmd & CMD_NR_MASK
    cmd_type = (cmd & CMD_TYPE_MASK) >> CMD_TYPE_SHIFT
    cmd_size = (cmd & CMD_SIZE_MASK) >> CMD_SIZE_SHIFT
    cmd_dir = (cmd & CMD_DIR_MASK) >> CMD_DIR_SHIFT
    return f"{cmd_type},{cmd_dir},{cmd_nr}"


# step 1: parse ouptut of interface extraction
# step 2: resolve all dynamic calls for each of the interfaces iteratively
# step 3: for any pair of interfaces, check for dependency
# step 4: output results for post analysis (or perform post analysis)

class Syscall:
    def __init__(self, name, input_res, output, ind, variant):
        self.name = name
        self.input_res = input_res
        self.output = output
        self.ind = ind
        self.variant = variant
        self.entryfunctions = []
        self.queries = []

class ResourceAPI:
    def __init__(self, constructor, calls, variants):
        self.constructor = constructor
        self.calls = [constructor] + calls # constructor is always the first call
        self.variants = variants
        self.name_to_ind = {}
        for i in range(0, len(self.calls)):
            self.name_to_ind[self.calls[i].name] = i
        self.deps = None
        self.multires_stats = {"kept" : 0, "skipped" : 0}

    def create_query(self, struct, offset):
        raise Exception("Not implemented")

    def to_string(self):
        raise Exception("Not implemented")

    def get_filename(self):
        raise Exception("Not implemented")

    def needs_special(self):
        return False

class ResourceAPINW(ResourceAPI):
    def __init__(self, family, sock_type, protocol, constructor, calls, variants):
        super().__init__(constructor, calls, variants)
        self.family = family
        self.sock_type = sock_type
        self.protocol = protocol

    def create_query(self, struct, offset):
        return Query(self.family, self.sock_type, self.protocol, struct, offset, None)

    def to_string(self):
        return f"{self.family} {self.sock_type} {self.protocol}"

    def get_filename(self):
        return f"{self.family}_{self.sock_type}_{self.protocol}"

    def needs_special(self):
        return True

class ResourceAPIDriver(ResourceAPI):
    def __init__(self, driverfiles, constructor, calls, variants):
        super().__init__(constructor, calls, variants)
        self.driverfiles = driverfiles

    def create_query(self, struct, offset):
        return Query(0, 0, 0, struct, offset, self.driverfiles)

    def to_string(self):
        return f"{self.driverfiles[0]}"

    def get_filename(self):
        return self.to_string().replace("/", "_")[1:]


class Dependency:
    def __init__(self, setter, checker, depvalue, sfile, sline,
                 cfile, cline, variant):
        self.setter = setter
        self.checker = checker
        self.depvalue = depvalue
        self.sfile = sfile
        self.sline = sline
        self.cfile = cfile
        self.cline = cline
        self.variant = variant
        self.setter_res = None
        self.checker_res = None

class Worker:
    def __init__(self, workdir, codeqldb, input_dir,
                 query_template_dir, verbose):
        self.workdir = workdir
        self.codeqldb = codeqldb
        self.input_dir = input_dir
        self.query_template_dir = query_template_dir
        self.verbose = verbose
        self.codeql = CodeQLAPI(self.workdir, self.codeqldb, self.verbose)
        self.qb = QueryBuilder(self.query_template_dir)
        self.dfpr = DynamicFuncPtrResolution(os.path.join(self.input_dir, "network_data.bin"),
                                        os.path.join(self.input_dir, "fd_data.bin"),
                                        os.path.join(self.input_dir, "network_stack_info.txt"),
                                        os.path.join(self.input_dir, "vmlinux"),
                                        os.path.join(self.input_dir, "parsing_cache.bin"))
        self.dfpr.parse()
        self.apis = []
        self.depCount = defaultdict(int)
        self.multires_allowed = set()
        self.multires_stats = {"kept" : 0, "skipped" : 0}
        self._parse_interfaces_nw()
        self._parse_interfaces_dr()

    def _parse_interfaces_dr(self):
        """ Parse the output of driver interface extraction. """

        with open(os.path.join(self.input_dir, "driver_interfaces.txt"), 'r') as f:
            lines = f.readlines()
        interfaces = []
        i = 0
        while i < len(lines):
            if lines[i][:6] != "Paths:":
                print("Error: invalid format for interface file (driver)")
                print(i)
                sys.exit(1)
            i += 1
            paths = []
            while i < len(lines) and not lines[i].startswith("Constructor:"):
                paths.append(lines[i].strip())
                i += 1

            if lines[i][:13] != "Constructor: ":
                print("Error: invalid format for interface file (constructor)")
                print(i)
                sys.exit(1)
            constructor = Syscall(lines[i][13:].strip(), [], True, 0, None)
            calls = []
            i += 1
            if lines[i].strip() != "Calls:":
                print("Error: invalid format for interface file (calls)")
                print(i)
                sys.exit(1)
            i += 1
            variants = {"ioctl": {}}
            while i < len(lines) and lines[i].strip() != "":
                sp = lines[i].strip().split(" ")
                syscall = Syscall(sp[0].strip(), [], False, len(calls)+1, None)
                if sp[0].startswith("ioctl"):
                    # check if it really is an int
                    try:
                        variants['ioctl'][int(sp[3].strip(), 10)] = len(calls) + 1
                        variants['ioctl'][sp[0].strip()] = int(sp[3].strip(), 10)
                        variants['ioctl'][cmd_to_str(int(sp[3].strip(), 10))] = len(calls) + 1
                        syscall.variant = int(sp[3].strip(), 10)
                    except ValueError:
                        pass
                for j in range(0, len(sp)-2):
                    if sp[j+2] == "r":
                        syscall.input_res.append(j)
                    elif sp[j+2] == "ret":
                        syscall.output = True
                calls.append(syscall)
                i += 1
            interfaces.append(ResourceAPIDriver(paths, constructor, calls, variants))
            i += 2

        self.apis.extend(interfaces)

    def _parse_interfaces_nw(self):
        """ Parse the output of network interface extraction. """

        with open(os.path.join(self.input_dir, "socket_interfaces.txt"), 'r') as f:
            lines = f.readlines()
        interfaces = []
        i = 0
        while i < len(lines):
            if lines[i][:8] != "Family: ":
                print("Error: invalid format for interface file (family)")
                print(i)
                sys.exit(1)
            family = int(lines[i][8:].strip())
            if lines[i+1][:10] != "SockType: ":
                print("Error: invalid format for interface file (socktype)")
                print(i)
                sys.exit(1)
            sock_type = int(lines[i+1][10:].strip())
            if lines[i+2][:10] != "Protocol: ":
                print("Error: invalid format for interface file (protocol)")
                print(i)
                sys.exit(1)
            protocol = int(lines[i+2][10:].strip())
            if lines[i+3][:13] != "Constructor: ":
                print("Error: invalid format for interface file (constructor)")
                print(i)
                sys.exit(1)
            constructor = Syscall(lines[i+3][13:].strip(), [], True, 0, None)
            calls = []
            i += 4
            if lines[i].strip() != "Calls:":
                print("Error: invalid format for interface file (calls)")
                print(i)
                sys.exit(1)
            i += 1
            variants = {"setsockopt": {}, "getsockopt": {}, "ioctl": {}}
            while i < len(lines) and lines[i].strip() != "":
                sp = lines[i].strip().split(" ")
                syscall = Syscall(sp[0].strip(), [], False, len(calls)+1, None)
                if sp[0].startswith("setsockopt"):
                    # check if it really is an int
                    try:
                        variants['setsockopt'][int(sp[4].strip(), 10)] = len(calls) + 1
                        variants['setsockopt'][sp[0].strip()] = int(sp[4].strip(), 10)
                        syscall.variant = int(sp[4].strip(), 10)
                    except ValueError:
                        pass
                elif sp[0].startswith("getsockopt"):
                    try:
                        variants['getsockopt'][int(sp[4].strip(), 10)] = len(calls) + 1
                        variants['getsockopt'][sp[0].strip()] = int(sp[4].strip(), 10)
                        syscall.variant = int(sp[4].strip(), 10)
                    except ValueError:
                        pass
                elif sp[0].startswith("ioctl"):
                    # check if it really is an int
                    try:
                        variants['ioctl'][int(sp[3].strip(), 10)] = len(calls) + 1
                        variants['ioctl'][sp[0].strip()] = int(sp[3].strip(), 10)
                        variants['ioctl'][cmd_to_str(int(sp[3].strip(), 10))] = len(calls) + 1
                        syscall.variant = int(sp[3].strip(), 10)
                    except ValueError:
                        pass

                for j in range(0, len(sp)-2):
                    if sp[j+2] == "r":
                        syscall.input_res.append(j)
                    elif sp[j+2] == "ret":
                        syscall.output = True

                calls.append(syscall)
                i += 1
            interfaces.append(ResourceAPINW(family, sock_type, protocol, constructor, calls, variants))
            i += 2

        self.apis.extend(interfaces)

    def _create_targetLookup_pred(self, syscall):
        """ Create the predicate to lookup indirect calls for a syscall.

        Note: This function requires self.dfpr to be set and not shut down.
        """

        lookups = []
        for q in syscall.queries:
            lookups.append(LookupResult(q, self.dfpr.executeQuery(q)))
        pred = self.qb.get_targetLookup_pred(lookups)

        return pred

    def _parse_indir_result(self, results, k, state, api):
        """ Parse one result of indirect call resolution. """

        key = int(k)
        syscall = api.calls[key]
        #key = res['key']
        funcs = results[k]
        #funcs = res['results']
        new_funcs = []
        seen = state[key]['seen']
        setsockopt_funcs = []
        getsockopt_funcs = []
        ioctl_funcs = []
        for f in funcs:
            t = f['message'].split("|")
            struct = t[0].strip()
            offset = int(t[1].strip())
            field = t[2].strip()
            query = api.create_query(struct, offset)
            #query = Query(api.family, api.sock_type, api.protocol, struct, offset, None)
            n_fs = self.dfpr.executeQuery(query)
            for n_f in n_fs:
                if n_f not in seen:
                    if field == "setsockopt":
                        if not 'entrypoint' in api.variants['setsockopt']:
                            api.variants['setsockopt']['entrypoint'] = []
                        if not n_f in api.variants['setsockopt']['entrypoint']:
                            api.variants['setsockopt']['entrypoint'].append(n_f)
                            setsockopt_funcs.append(n_f)
                            syscall.queries.append(query)
                    elif field == "getsockopt":
                        if not 'entrypoint' in api.variants['getsockopt']:
                            api.variants['getsockopt']['entrypoint'] = []
                        if not n_f in api.variants['getsockopt']['entrypoint']:
                            api.variants['getsockopt']['entrypoint'].append(n_f)
                            getsockopt_funcs.append(n_f)
                            syscall.queries.append(query)
                    elif field == "ioctl":
                        if not 'entrypoint' in api.variants['ioctl']:
                            api.variants['ioctl']['entrypoint'] = []
                        if not n_f in api.variants['ioctl']['entrypoint']:
                            api.variants['ioctl']['entrypoint'].append(n_f)
                            ioctl_funcs.append(n_f)
                            syscall.queries.append(query)
                    else:
                        syscall.entryfunctions.append(n_f)
                        #api.entryfunctions[key].append(n_f)
                        syscall.queries.append(query)
                        #api.queries[key].add(query)
                        new_funcs.append(n_f)
                    seen.add(n_f)

        if (new_funcs or setsockopt_funcs or getsockopt_funcs or
            ioctl_funcs):
            state[key]['new_funcs'] = new_funcs
            state[key]['setsockopt_funcs'] = setsockopt_funcs
            state[key]['getsockopt_funcs'] = getsockopt_funcs
            state[key]['ioctl_funcs'] = ioctl_funcs
            state[key]['seen'] = seen
        else:
            del state[key]
            if self.verbose:
                print(f"[*] Resolved {len(syscall.entryfunctions)} indirect calls for {syscall.name}")
                print(syscall.entryfunctions)



    def _handle_api(self, api):
        """ Resolve all indirect calls in a single API.

        Note: This function requires self.dfpr to be set and not shut down.
        """

        # run the query for the most general entry point
        # collect the resulting dynamic dereferences
        # query dfpr for each of them
        # as long as we find new functions: run the query on these functions

        if self.verbose:
            print(f"[*]Resolving indirect calls for {api.to_string()}")

        state = {}

        # add query for the constructor
        if api.needs_special():
            start = 1
            if len(api.calls[0].entryfunctions) == 0:
                call = api.calls[0]
                self.codeql._cleanup_codeql_dir()
                q = self.qb.get_init_func_query(api.family)
                self.codeql._add_codeql_query(q, 0)
                results = self.codeql._run_all_queries()
                call.entryfunctions = ["__do_sys_" + call.name.split("$")[0]]
                new_funcs = ["__do_sys_" + call.name.split("$")[0]] 
                call.queries = []
                for k in results:
                    if int(k) != api.family:
                        continue
                    funcs = results[k]
                    for f in funcs:
                        call.entryfunctions.append(f['message'])
                        new_funcs.append(f['message'])
                        state[0] = {'seen': set(), 'new_funcs': new_funcs}
                        break
        else:
            start = 0

        # populate starting state with the entrypoint for all syscalls
        for i in range(start, len(api.calls)):
            syscall = api.calls[i]
            if syscall.entryfunctions is not None and len(syscall.entryfunctions) > 0:
                continue
            if syscall.name.startswith("syz"):
                #pseudo call, let's skip for now
                continue
            syscall_name = syscall.name.split("$")[0]
            syscall.entryfunctions = ["__do_sys_" + syscall_name]
            syscall.queries = []
            seen = set()
            new_funcs = ["__do_sys_" + syscall_name]
            state[i] = {'seen': seen, 'new_funcs': new_funcs}

        # resolve the two possible locations for the setsockopt functions
        # and add them to the state
        if "setsockopt" in api.variants:
            query = api.create_query('proto_ops', 112)
            #query = Query(api.family, api.sock_type, api.protocol, 'proto_ops', 112, None) # TODO hardcoded for v6.6-rc7 db
            fs = self.dfpr.executeQuery(query)
            query2 = api.create_query('proto', 72)
            #query2 = Query(api.family, api.sock_type, api.protocol, 'proto', 72, None) # TODO hardcoded for v6.6-rc7 db
            fs.extend(self.dfpr.executeQuery(query2))
            for key in state:
                if api.calls[key].name.startswith("setsockopt"):
                    state[key]['setsockopt_funcs'] = []
                    state[key]['setsockopt_funcs'].extend(fs)
            api.variants['setsockopt']['entrypoint'] = fs

            # these queries are needed for the tain tracking. the taint
            # tracking doesn't need to be aware of different opts, since
            # it will only receive deps that already respect the opt
            # boundaries.
            for syscall in api.calls:
                if syscall.name.startswith("setsockopt"):
                    syscall.queries.append(query)
                    syscall.queries.append(query2)

        # as above
        if "getsockopt" in api.variants:
            query = api.create_query('proto_ops', 120)
            #query = Query(api.family, api.sock_type, api.protocol, 'proto_ops', 120, None) # TODO hardcoded for v6.6-rc7 db
            fs = self.dfpr.executeQuery(query)
            query2 = api.create_query('proto', 80)
            #query2 = Query(api.family, api.sock_type, api.protocol, 'proto', 80, None) # TODO hardcoded for v6.6-rc7 db
            fs.extend(self.dfpr.executeQuery(query2))
            for key in state:
                if api.calls[key].name.startswith("getsockopt"):
                    state[key]['getsockopt_funcs'] = []
                    state[key]['getsockopt_funcs'].extend(fs)
            api.variants['getsockopt']['entrypoint'] = fs
            for syscall in api.calls:
                if syscall.name.startswith("getsockopt"):
                    syscall.queries.append(query)
                    syscall.queries.append(query2)

        # as above
        if "ioctl" in api.variants:
            query = api.create_query('file_operations', 80) # 72
            #query = Query(api.family, api.sock_type, api.protocol, 'file_operations', 0, None) # TODO hardcoded for v6.6-rc7 db
            fs = self.dfpr.executeQuery(query)
            query2 = api.create_query('file_operations', 72)
            fs.extend(self.dfpr.executeQuery(query2))
            for key in state:
                if api.calls[key].name.startswith("ioctl"):
                    state[key]['ioctl_funcs'] = []
                    state[key]['ioctl_funcs'].extend(fs)
            api.variants['ioctl']['entrypoint'] = fs
            for syscall in api.calls:
                if syscall.name.startswith("ioctl"):
                    syscall.queries.append(query)
                    syscall.queries.append(query2)

        while state:
            self.codeql._cleanup_codeql_dir()
            # register a query for every system call
            for key in state:
                new_funcs = state[key]['new_funcs']
                if len(new_funcs) > 0:
                    q = self.qb.get_deref_query(new_funcs, key)
                    self.codeql._add_codeql_query(q, key)

                syscall = api.calls[i]
                if ("setsockopt" in api.variants
                    and syscall.name in api.variants['setsockopt']):
                   if ("setsockopt_funcs" not in state[key]
                       or len(state[key]['setsockopt_funcs']) == 0):
                       continue
                   setsockopt_funcs = state[key]['setsockopt_funcs']
                   optval = api.variants['setsockopt'][key]
                   q = self.qb.get_sockopt_deref_query(setsockopt_funcs, key, optval)
                   self.codeql._add_codeql_query(q, key + "setsockopt")
                elif ("getsockopt" in api.variants
                      and syscall.name in api.variants['getsockopt']):
                   if ("getsockopt_funcs" not in state[key]
                       or len(state[key]['getsockopt_funcs']) == 0):
                       continue
                   getsockopt_funcs = state[key]['getsockopt_funcs']
                   optval = api.variants['getsockopt'][key]
                   q = self.qb.get_sockopt_deref_query(getsockopt_funcs,
                                                       key, optval, prefix="get")
                   self.codeql._add_codeql_query(q, key + "getsockopt")
                elif ("ioctl" in api.variants
                      and syscall.name in api.variants['ioctl']):
                    if ("ioctl_funcs" not in state[key]
                        or len(state[key]['ioctl_funcs']) == 0):
                        continue
                    ioctl_funcs = state[key]['ioctl_funcs']
                    ioctl_cmd = cmd_to_str(api.variants['ioctl'][key])
                    q = self.qb.get_ioctl_deref_query(ioctl_funcs, key, ioctl_cmd)
                    self.codeql._add_codeql_query(q, key + "ioctl")

            results = self.codeql._run_all_queries()

            # process results
            if len(results) == 0:
                break
            for k in results:
                self._parse_indir_result(results, k, state, api)


    def resolve_dynamic_calls(self):
        """ Resolve all dynamic calls for each of the interfaces iteratively. """

        # for each call in each interface
        for api in self.apis:
            self._handle_api(api)

    def _parse_general_query_result(self, deps, results, variant, entrypoints):
        """ Parses the list of results of the general-purpose dependency queries. """

        for r in results:
            # retrieve the actual function names
            if self.verbose:
                print("Message:", r['message'])
            m = r['message']
            m = m.split(" | ")
            assert len(m) == 8
            dependentfunc = m[0]
            prereq = m[1]
            for s1 in entrypoints[dependentfunc]:
                for s2 in entrypoints[prereq]:
                    if s1 == s2:
                        continue
                    if not s1 in deps:
                        deps[s1] = {}
                    if not s2 in deps[s1]:
                        deps[s1][s2] = []
                    value = m[3]
                    if variant in ["aeint", "fcint"]:
                        value += ":" + m[2]
                    deps[s1][s2].append(Dependency(s2, s1, value, m[6], m[7], m[4], m[5], variant))
                    #deps[s1][s2].append(Dependency(s2, s1, m[3] + ":" + m[2], m[6], m[7], m[4], m[5], variant))
                    self.depCount[value] += 1

    def _parse_general_int_query_result(self, deps, results, variant, entrypoints):
        """ Parses the list of results of the general-purpose int dependency queries. """

        for r in results:
            # retrieve the actual function names
            if self.verbose:
                print("Message:", r['message'])
            m = r['message']
            m = m.split(" | ")
            assert len(m) == 8
            dependentfunc = m[0]
            prereq = m[1]
            for s1 in entrypoints[dependentfunc]:
                for s2 in entrypoints[prereq]:
                    if s1 == s2:
                        continue
                    if not s1 in deps:
                        deps[s1] = {}
                    if not s2 in deps[s1]:
                        deps[s1][s2] = []
                    deps[s1][s2].append(Dependency(s2, s1, m[3] + ":" + m[2], m[6], m[7], m[4], m[5], variant))

    def _parse_variant_query_result(self, api, deps, results, variant, entrypoints):
        """ Parses the list of results of the variant dependency queries. """

        for r in results:
            if self.verbose:
                print("Message:", r['message'])
            m = r['message']
            m = m.split(" | ")
            assert len(m) == 8 or len(m) == 10
            if variant.startswith("optif"):
                if "," in m[3]:
                    cond = m[3]
                else:
                    cond = int(m[3], 10)
                if variant.startswith("optifset"):
                    cond = api.variants['setsockopt'][cond]
                elif variant.startswith("optifget"):
                    cond = api.variants['getsockopt'][cond]
                elif variant.startswith("optifioctl"):
                    cond = api.variants['ioctl'][cond]
                prereq = m[0]
                value = m[2]
                if "int" in variant:
                    value += ":" + m[1]
                for s2 in entrypoints[prereq]:
                    if cond == s2:
                        continue
                    if not cond in deps:
                        deps[cond] = {}
                    if not s2 in deps[cond]:
                        deps[cond][s2] = []
                    deps[cond][s2].append(Dependency(s2, cond, value, m[6], m[7], m[4], m[5], variant))
                    self.depCount[value] += 1
            elif variant.startswith("optfc"):
                if "," in m[3]:
                    setter = m[3]
                else:
                    setter = int(m[3], 10)
                if variant.startswith("optfcset"):
                    setter = api.variants['setsockopt'][setter]
                elif variant.startswith("optfcget"):
                    setter = api.variants['getsockopt'][setter]
                elif variant.startswith("optfcioctl"):
                    setter = api.variants['ioctl'][setter]
                dependentfunc = m[0]
                value = m[2]
                if "int" in variant:
                    value += ":" + m[1]
                for s1 in entrypoints[dependentfunc]:
                    if s1 == setter:
                        continue
                    if not s1 in deps:
                        deps[s1] = {}
                    if not setter in deps[s1]:
                        deps[s1][setter] = []
                    deps[s1][setter].append(Dependency(setter, s1, value, m[6], m[7], m[4], m[5], variant))
                    self.depCount[value] += 1
            elif variant == "optsq":
                if "," in m[2]:
                    setter = m[2]
                else:
                    setter = int(m[2], 10)
                if "," in m[3]:
                    cond = m[3]
                else:
                    cond = int(m[3], 10)
                set_kind = m[8]
                cond_kind = m[9]
                setter = api.variants[set_kind][setter]
                cond = api.variants[cond_kind][cond]
                value = m[1]
                if "int" in variant:
                    value += ":" + m[0]
                if cond == setter:
                    continue
                if cond not in deps:
                    deps[cond] = {}
                if setter not in deps[cond]:
                    deps[cond][setter] = []
                deps[cond][setter].append(Dependency(setter, cond, value, m[6], m[7], m[4], m[5], variant))
                self.depCount[value] += 1

    def _check_api_fast(self, api):
        """ Check all calls in a single API for dependencies with only 2 queries. """

        """
         - first, collect all entry point functions. Also, create a mapping from
           function to all relevant syscalls
         - then, create the queries for FC and AE, that now print the two
           dependent functions
         - parse the results, only keep depedencies that actually correspond to
           two syscall entrypoints
        """

        if self.verbose:
            print(f"[*]Checking dependencies for {api.to_string()}")

        self.codeql._cleanup_codeql_dir()

        # as multires stuff removes duplicates, we need to regenerate deps every time
        #if api.deps is not None:
        #    return

        # collect all entry point functions
        entrypoints = defaultdict(list)
        for i in range(len(api.calls)):
            syscall = api.calls[i]
            if not syscall.entryfunctions:
                continue
            for f in syscall.entryfunctions:
                entrypoints[f].append(i)
        opts = {"setsockopt": [], "getsockopt": [], "ioctl": []}
        if "setsockopt" in api.variants:
            for k in api.variants['setsockopt']:
                if k == "entrypoint" or not isinstance(k, int):
                    continue
                opts['setsockopt'].append(k)
        if "getsockopt" in api.variants:
            for k in api.variants['getsockopt']:
                if k == "entrypoint" or not isinstance(k, int):
                    continue
                opts['getsockopt'].append(k)
        if "ioctl" in api.variants:
            for k in api.variants['ioctl']:
                if k == "entrypoint" or not isinstance(k, int):
                    continue
                opts['ioctl'].append(cmd_to_str(k))

        # create the queries
        q1 = self.qb.get_assign_deps_query(entrypoints)
        self.codeql._add_codeql_query(q1, "ae")

        q2 = self.qb.get_setter_deps_query(entrypoints)
        self.codeql._add_codeql_query(q2, "fc")

        # add int ae and fc queries
        q8 = self.qb.get_setter_deps_int_query(entrypoints)
        self.codeql._add_codeql_query(q8, "fcint")

        q9 = self.qb.get_assign_deps_int_query(entrypoints)
        self.codeql._add_codeql_query(q9, "aeint")

        # generate separate queries for setsockopt
        if len(opts['setsockopt']) > 0:
            q3 = self.qb.get_setter_deps_sso_fc(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'])
            self.codeql._add_codeql_query(q3, "optfcset")

            q31 = self.qb.get_setter_deps_sso_fc(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'],
                                                 int_variant=True)
            self.codeql._add_codeql_query(q31, "optfcsetint")

            q4 = self.qb.get_setter_deps_sso_if(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'])
            self.codeql._add_codeql_query(q4, "optifset")

            q41 = self.qb.get_setter_deps_sso_if(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'],
                                                int_variant=True)
            self.codeql._add_codeql_query(q41, "optifsetint")

            q12 = self.qb.get_setter_deps_sso_ae(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'])
            self.codeql._add_codeql_query(q12, "optaeset")

            q121 = self.qb.get_setter_deps_sso_ae(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'],
                                                int_variant=True)
            self.codeql._add_codeql_query(q121, "optaesetint")

            q13 = self.qb.get_setter_deps_sso_if_ae(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'])
            self.codeql._add_codeql_query(q13, "optifsetae")

            q131 = self.qb.get_setter_deps_sso_if_ae(entrypoints, opts['setsockopt'],
                                                api.variants['setsockopt']['entrypoint'],
                                                int_variant=True)
            self.codeql._add_codeql_query(q131, "optifsetaeint")

        if len(opts['getsockopt']) > 0:
            q5 = self.qb.get_setter_deps_sso_fc(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get')
            self.codeql._add_codeql_query(q5, "optfcget")

            q51 = self.qb.get_setter_deps_sso_fc(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get', int_variant=True)
            self.codeql._add_codeql_query(q51, "optfcgetint")

            q6 = self.qb.get_setter_deps_sso_if(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get')
            self.codeql._add_codeql_query(q6, "optifget")

            q61 = self.qb.get_setter_deps_sso_if(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get', int_variant=True)
            self.codeql._add_codeql_query(q61, "optifgetint")

            q14 = self.qb.get_setter_deps_sso_ae(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get')
            self.codeql._add_codeql_query(q14, "optaeget")

            q141 = self.qb.get_setter_deps_sso_ae(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get', int_variant=True)
            self.codeql._add_codeql_query(q141, "optaegetint")

            q15 = self.qb.get_setter_deps_sso_if_ae(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get')
            self.codeql._add_codeql_query(q15, "optifgetae")

            q151 = self.qb.get_setter_deps_sso_if_ae(entrypoints, opts['getsockopt'],
                                                api.variants['getsockopt']['entrypoint'],
                                                suffix='get', int_variant=True)
            self.codeql._add_codeql_query(q151, "optifgetaeint")

        if len(opts['ioctl']) > 0:
            max_opts = 50
            for i in range(0, len(opts['ioctl']), max_opts):
                end = min(i+max_opts, len(opts['ioctl']))
                q10 = self.qb.get_setter_deps_ioctl_fc(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i)
                self.codeql._add_codeql_query(q10, f"optfcioctl{i}")

                q101 = self.qb.get_setter_deps_ioctl_fc(entrypoints, opts['ioctl'][i:end],
                                                        api.variants['ioctl']['entrypoint'], i,
                                                        int_variant=True)
                self.codeql._add_codeql_query(q101, f"optfcioctlint{i}")

                q11 = self.qb.get_setter_deps_ioctl_if(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i)
                self.codeql._add_codeql_query(q11, f"optifioctl{i}")

                q111 = self.qb.get_setter_deps_ioctl_if(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i,
                                                    int_variant=True)
                self.codeql._add_codeql_query(q111, f"optifioctlint{i}")

                q16 = self.qb.get_setter_deps_ioctl_ae(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i)
                self.codeql._add_codeql_query(q16, f"optaeioctl{i}")

                q161 = self.qb.get_setter_deps_ioctl_ae(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i,
                                                    int_variant=True)
                self.codeql._add_codeql_query(q161, f"optaeioctlint{i}")

                q17 = self.qb.get_setter_deps_ioctl_if_ae(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i)
                self.codeql._add_codeql_query(q17, f"optifioctlae{i}")

                q171 = self.qb.get_setter_deps_ioctl_if_ae(entrypoints, opts['ioctl'][i:end],
                                                    api.variants['ioctl']['entrypoint'], i,
                                                    int_variant=True)
                self.codeql._add_codeql_query(q171, f"optifioctlaeint{i}")

        if len(opts['setsockopt']) > 0 or len(opts['getsockopt']) > 0 or len(opts['ioctl']) > 0:
            opt_entrypoints = {"setsockopt": [], "getsockopt": []}
            if "setsockopt" in api.variants and "entrypoint" in api.variants['setsockopt']:
                opt_entrypoints["setsockopt"] = api.variants['setsockopt']['entrypoint']
            if "getsockopt" in api.variants and "entrypoint" in api.variants['getsockopt']:
                opt_entrypoints["getsockopt"] = api.variants['getsockopt']['entrypoint']
            q7 = self.qb.get_setter_deps_sso_square(opts, opts, opt_entrypoints,
                                                    opts['ioctl'],
                                                    api.variants['ioctl']['entrypoint'])
            self.codeql._add_codeql_query(q7, "optsq")

            q71 = self.qb.get_setter_deps_sso_square(opts, opts, opt_entrypoints,
                                                    opts['ioctl'],
                                                    api.variants['ioctl']['entrypoint'],
                                                    int_variant=True)
            self.codeql._add_codeql_query(q71, "optsqint")

            q18 = self.qb.get_setter_deps_sso_square_ae(opts, opts, opt_entrypoints,
                                                    opts['ioctl'],
                                                    api.variants['ioctl']['entrypoint'])
            self.codeql._add_codeql_query(q18, "optsqae")

            q181 = self.qb.get_setter_deps_sso_square_ae(opts, opts, opt_entrypoints,
                                                    opts['ioctl'],
                                                    api.variants['ioctl']['entrypoint'],
                                                    int_variant=True)
            self.codeql._add_codeql_query(q181, "optsqaeint")

        # run the queries
        results = self.codeql._run_all_queries(big=True)

        # parse the results
        deps = {}
        for k in results:
            if k in ["ae", "fc", "fcint", "aeint"]:
                self._parse_general_query_result(deps, results[k], k, entrypoints)
            elif k in ["optfcset", "optifset", "optfcget", "optifget", "optsq", "optfcioctl", "optifioctl",
                       "optfcsetint", "optifsetint", "optfcgetint", "optifgetint", "optfcioctlint", "optifioctlint",
                       "optaeset", "optifsetae", "optaeget", "optifgetae", "optaesetint", "optifsetaeint", "optaegetint",
                       "optifgetaeint", "optaeioctl", "optifioctlae", "optaeioctlint", "optifioctlaeint", "optsqint",
                       "optsqae", "optsqaeint"]:
                self._parse_variant_query_result(api, deps, results[k], k, entrypoints)
            else:
                print("Unknown query result key:", k)
                assert False
        if self.verbose:
            for k in entrypoints:
                print(f"{k}: ", end="")
                for s in entrypoints[k]:
                    print(f"{api.calls[s].name} ", end="")
                print()
        api.deps = deps

    def check_dependency(self):
        """ Find dependencies between the calls of all apis. """

        # for each call in each interface
        for api in self.apis:
            self._check_api_fast(api)

    def _parse_multi_res_result(self, results, k, loc_2_deps):
        """ Consumre CodeQL results and update deps accordingly. """

        kind = ""
        if k.startswith("if"):
            kind = "checker"
        else:
            kind = "setter"

        for result in results:
            m = result['message']
            sp = m.split(" | ")
            assert len(sp) == 5
            ind = int(sp[0])
            file = sp[1]
            line = sp[2]
            val = sp[3]
            syscall_name = sp[4]
            """
            if idx != int(sp[5]):
                # check if it is the right api
                continue
            """
            deps = loc_2_deps[(file, line, syscall_name)][(kind, val)]
            for dep in deps:
                if kind == "checker":
                    dep[0].checker_res = ind
                    #assert dep.checker == syscall_id
                else:
                    dep[0].setter_res = ind
                    #assert dep.setter == syscall_id
                # for debugging, to make sure this whole thing is really by reference
                #assert dep in api.deps[dep.checker][dep.setter]

    def _register_multires_queries(self, loc_2_deps):
        """ Given a list of dependencies, generate all required queries. """

        count = 0
        for loc in loc_2_deps:
            for inst in loc_2_deps[loc]:
                """
                if inst[1] not in self.multires_allowed:
                    self.multires_stats["skipped"] += 1
                    api.multires_stats["skipped"] += 1
                    # ensure that prob is now distributed equally
                    # for each possible resource, add a dep object to api.deps
                    # each object will have the resource id set already
                    for dep in loc_2_deps[loc][inst]:
                        if inst[0] == "setter" and not dep.setter_res is None:
                            # we may have already seen this combination through the checker
                            continue
                        if inst[0] == "checker" and not dep.checker_res is None:
                            # we may have already seen this combination through the setter
                            continue
                        setter_rs = api.calls[dep.setter].input_res
                        if api.calls[dep.setter].output:
                            setter_rs.append('r')
                        checker_rs = api.calls[dep.checker].input_res
                        for i in range(len(setter_rs)):
                            for j in range(len(checker_rs)):
                                if i == j == 0:
                                    dep.setter_res = setter_rs[i]
                                    dep.checker_res = checker_rs[j]
                                else:
                                    d = Dependency(dep.setter, dep.checker, dep.depvalue,
                                                   dep.sfile, dep.sline, dep.cfile,
                                                   dep.cline, dep.variant)
                                    d.setter_res = setter_rs[i]
                                    d.checker_res = checker_rs[j]
                                    api.deps[dep.checker][dep.setter].append(d)

                    continue
                else:
                    self.multires_stats["kept"] += 1
                    api.multires_stats["kept"] += 1
                """
                deps = loc_2_deps[loc][inst]
                # if it is a checker, register the query and move on, if it is a setter, checker which of the two queries we need to register (potentially both)
                syscall = loc[2]
                target_lookup = deps[0][1]
                if inst[0] == "checker":
                    if ":" in inst[1]:
                        query = self.qb.get_multi_res_if_int_query(target_lookup, loc[0], loc[1], inst[1],
                                            "__do_sys_" + syscall.split("$")[0], count, loc[2])
                    else:
                        query = self.qb.get_multi_res_if_query(target_lookup, loc[0], loc[1], inst[1],
                                                "__do_sys_" + syscall.split("$")[0], count, loc[2])
                    self.codeql._add_codeql_query(query, "multi_res" + str(count))
                    count += 1
                elif inst[0] == "setter":
                    ae = False
                    fc = False
                    aeint = False
                    fcint = False
                    for dep_pair in deps:
                        dep = dep_pair[0]
                        ae_tags = ["ae", "optaeset", "optifsetae", "optaeget", "optifgetae", "optaeioctl",
                                   "optifioctlae", "optsqae"]
                        ae_int_tags = ["aeint", "optaesetint", "optifsetaeint", "optaegetint", "optifgetaeint",
                                        "optaeioctlint", "optifioctlaeint", "optsqaeint"]
                        fc_tags = ["fc", "optifget", "optifset", "optfcget", "optifioctl", "optfcset",
                                   "optfcioctl", "optsq"]
                        fc_int_tags = ["fcint", "optifgetint", "optifsetint", "optfcgetint", "optifioctlint",
                                       "optfcsetint", "optfcioctlint", "optsqint"]
                        if dep.variant in ae_tags and not ae:
                            query = self.qb.get_multi_res_ae_query(target_lookup, loc[0], loc[1], inst[1],
                                                                   "__do_sys_" + syscall.split("$")[0],
                                                                   count, loc[2])
                            ae = True
                            self.codeql._add_codeql_query(query, "multi_res" + str(count))
                            count += 1
                        elif dep.variant in fc_tags and not fc:
                            query = self.qb.get_multi_res_fc_query(target_lookup, loc[0], loc[1], inst[1],
                                                                   "__do_sys_" + syscall.split("$")[0],
                                                                   count, loc[2])
                            self.codeql._add_codeql_query(query, "multi_res" + str(count))
                            count += 1
                            fc = True
                        elif dep.variant in ae_int_tags and not aeint:
                            query = self.qb.get_multi_res_ae_int_query(target_lookup, loc[0], loc[1], inst[1],
                                                                       "__do_sys_" + syscall.split("$")[0],
                                                                       count, loc[2])
                            aeint = True
                            self.codeql._add_codeql_query(query, "multi_res" + str(count))
                            count += 1
                        elif dep.variant in fc_int_tags and not fcint:
                            query = self.qb.get_multi_res_fc_int_query(target_lookup, loc[0], loc[1], inst[1],
                                                                       "__do_sys_" + syscall.split("$")[0],
                                                                       count, loc[2])
                            self.codeql._add_codeql_query(query, "multi_res" + str(count))
                            count += 1
                            fcint = True
                        if ae and fc and aeint and fcint:
                            break


    def _deduplicate(self, deps):
        """Given a list of dependencies, return a list of unique dependencies. 

        This function assumes that the list of dependencies only contains
        dependencies between 2 syscalls.
        """

        unique = []
        seen = set()
        for dep in deps:
            if not (dep.depvalue, dep.setter_res, dep.checker_res) in seen:
                unique.append(dep)
                seen.add((dep.depvalue, dep.setter_res, dep.checker_res))
            if self.verbose:
                print("Dropping duplicate")
        return unique


    def _multi_resource(self, apis, skip):
        """ Find multi-resource dependencies and register queries. """

        # collect dependencies that contain calls with multiple resources
        deps = []
        for api in apis:
            if api.deps is None:
                continue
            for i in api.deps:
                for j in api.deps[i]:
                    if api.deps[i][j]:
                        for dep in api.deps[i][j]:
                            setter = api.calls[j]
                            checker = api.calls[i]
                            kind = []
                            if len(setter.input_res) > 1 or (len(setter.input_res) == 1 and setter.output):
                                kind.append("setter")
                            if len(checker.input_res) > 1:
                                kind.append("checker")
                            if len(kind) > 0:
                                if dep.depvalue in skip:
                                    setter_rs = []
                                    setter_rs.extend(setter.input_res)
                                    if setter.output:
                                        setter_rs.append('r')
                                    checker_rs = []
                                    checker_rs.extend(checker.input_res)
                                    for i in range(len(setter_rs)):
                                        for j in range(len(checker_rs)):
                                            if i == j == 0:
                                                dep.setter_res = setter_rs[i]
                                                dep.checker_res = checker_rs[j]
                                            else:
                                                d = Dependency(j, i, dep.depvalue,
                                                               dep.sfile, dep.sline,
                                                               dep.cfile, dep.cline,
                                                               dep.variant)
                                                d.setter_res = setter_rs[i]
                                                d.checker_res = checker_rs[j]
                                                api.deps[i][j].append(d)
                                else:
                                    deps.append((dep, kind, api))

        # collect all locations that need to be assigned a resource (i.e., a function
        # call in file x in line y needs to be related to either arg1 or arg2)
        # keep a reference of which deps need this information
        # maybe build a map with keys (file, line, syscall entry point), (dependency type, value), and values being the deps that correspond to this
        loc_2_deps = {}
        for dep, kind, api in deps:
            if "setter" in kind:
                key = (dep.sfile, dep.sline, api.calls[dep.setter].name)
                if not key in loc_2_deps:
                    loc_2_deps[key] = {}
                target_lookup = ""
                if ("setter", dep.depvalue) not in loc_2_deps[key]:
                    loc_2_deps[key][("setter", dep.depvalue)] = []
                    target_lookup = self._create_targetLookup_pred(api.calls[dep.setter])
                loc_2_deps[key][("setter", dep.depvalue)].append((dep, target_lookup))
            if "checker" in kind:
                key = (dep.cfile, dep.cline, api.calls[dep.checker].name)
                if not key in loc_2_deps:
                    loc_2_deps[key] = {}
                target_lookup = ""
                if ("checker", dep.depvalue) not in loc_2_deps[key]:
                    loc_2_deps[key][("checker", dep.depvalue)] = []
                    target_lookup = self._create_targetLookup_pred(api.calls[dep.checker])
                loc_2_deps[key][("checker", dep.depvalue)].append((dep, target_lookup))

        self._register_multires_queries(loc_2_deps)
        return loc_2_deps

    def _run_multi_resource_queries(self):
        """ Run all multi-resource queries. """
        # NOTE: for now, we will just clear the cache before and after this and let it run for a long time
        # if it is too slow, we can try and make batched processing work
        self.codeql._cleanup_database_cache()
        results = self.codeql._run_all_queries(big=True, debug=DEBUG)
        self.codeql._cleanup_database_cache()

        return results

    def _consume_multi_resource_results(self, results, loc_2_deps):
        """ Consume the results of the multi-resource queries. """
        for k in results:
            self._parse_multi_res_result(results[k], k, loc_2_deps)
        # for the remaining dependencies, mark the resource as the return value
        for loc in loc_2_deps:
            for inst in loc_2_deps[loc]:
                for dep in loc_2_deps[loc][inst]:
                    if inst[0] == "checker":
                        if dep[0].checker_res is not None:
                            continue
                        dep[0].checker_res = 'r'
                    elif inst[0] == "setter":
                        if dep[0].setter_res is not None:
                            continue
                        dep[0].setter_res = 'r'

    def _find_allowed_multires(self):
        """ Determine which dependencies can be resolved with multi-resource. """

        depCount = defaultdict(int)
        for api in self.apis:
            if api.deps is None:
                continue
            for i in api.deps:
                for j in api.deps[i]:
                    if api.deps[i][j]:
                        for dep in api.deps[i][j]:
                            depCount[dep.depvalue] += 1

        dep_list = []
        for dep in depCount:
            dep_list.append((depCount[dep], dep))
        dep_list = sorted(dep_list)
        """
        allowed_num = (2*len(dep_list))//3
        for i in range(allowed_num):
            self.multires_allowed.add(dep_list[i][1])
        """
        return dep_list[0][1]


    def find_n_resolve_multi_res(self):
        """ For all apis, find and resolve multi-resource dependencies. """

        # identify dep values that we want to run this for
        skip = [self._find_allowed_multires()]

        self.codeql._cleanup_codeql_dir()
        api_locs = []
        loc_2_deps = self._multi_resource(self.apis, skip)
        """
        for i in range(len(self.apis)):
            api_locs.append(self._multi_resource(self.apis[i], i))
        """

        results = self._run_multi_resource_queries()

        self._consume_multi_resource_results(results, loc_2_deps)
        """
        for i in range(len(self.apis)):
            self._consume_multi_resource_results(results, api_locs[i], self.apis[i], i)
        """

        # we now need some deduplication of deps since there might be multiple per resource
        # two dependencies are the same if they have the same setter, checker, depvalue, setter_res, checker_res
        for api in self.apis:
            if api.deps is None:
                continue
            for checker in api.deps:
                for setter in api.deps[checker]:
                    api.deps[checker][setter] = self._deduplicate(api.deps[checker][setter])

        """
        print(f"[*] Multi-resource stats: {self.multires_stats}")
        for i in range(len(self.apis)):
            print(f"[*] Multi-resource stats for {self.apis[i].to_string()}: {self.apis[i].multires_stats}")
        """

    def _output_results_human_list(self):
        """ Print list of dependencies to stdout. """

        for api in self.apis:
            if api.deps is None:
                continue
            for i in api.deps:
                for j in api.deps[i]:
                    if api.deps[i][j]:
                        deps = list(set([d.depvalue for d in api.deps[i][j]]))
                        print(f"[*] Found dependency: call {api.calls[j].name} before {api.calls[i].name} ({deps})")

    def _output_results_graph(self):
        """ Output results as a graph. """

        seen = set()
        for api in self.apis:
            if api.deps is None:
                continue
            dot_graph = "digraph dependencies {\n"
            dot_graph += "\tnode [fontsize=40.0];\n"
            for i in api.deps:
                for j in api.deps[i]:
                    if api.deps[i][j]:
                        for d in api.deps[i][j]:
                            """
                            if d.depvalue == "TCP_CLOSE": # or d.depvalue == "PIDTYPE_PID" or d.depvalue[:4] == "RPM_":
                                continue
                            if (api.calls[j].name[:8] == "sendmsg$" or api.calls[i].name[:8] == "sendmsg$"
                                or api.calls[j].name[:9] == "sendmmsg$" or api.calls[i].name[:9] == "sendmmsg$"
                                or api.calls[j].name[:7] == "sendto$" or api.calls[i].name[:7] == "sendto$"
                                or api.calls[j].name[:8] == "connect$" or api.calls[i].name[:8] == "connect$"
                                or api.calls[j].name[:7] == "accept$" or api.calls[i].name[:7] == "accept$"):
                                continue
                            """
                            if (api.calls[j].name, api.calls[i].name) in seen:
                                continue
                            seen.add((api.calls[j].name, api.calls[i].name))
                            dot_graph += f"\t\"{api.calls[i].name}\" -> \"{api.calls[j].name}\"\n"# [label=\"{d.depvalue}\"];\n"
            dot_graph += "}\n"
            with open(f"{self.workdir}/{api.get_filename()}.dot", "w") as f:
                f.write(dot_graph)
            return
            subprocess.run([
                    "sfdp", "-x", "-Goverlap=prism", "-Tpng",
                    f"{self.workdir}/{api.get_filename()}.dot",
                    "-o", f"{self.workdir}/{api.get_filename()}.png"
                ])

    def _build_forward_map(self, probs, merged_deps):
        """ Build and store a forward map of dependencies. """

        # per checker, calculate prop for each possible setter
        # build both JSON maps
        json_out = {"syscall_level" : {}, "resource_level" : {}}
        for checker in merged_deps:
            if not checker in json_out["syscall_level"]:
                json_out["syscall_level"][checker] = {}
            total_prob = 0
            for setter in merged_deps[checker]:
                if not setter in json_out["syscall_level"][checker]:
                    json_out["syscall_level"][checker][setter] = 0
                for dep in merged_deps[checker][setter]:
                    json_out["syscall_level"][checker][setter] += probs[dep.depvalue]
                    total_prob += probs[dep.depvalue]
            # normalize
            for setter in json_out["syscall_level"][checker]:
                json_out["syscall_level"][checker][setter] /= total_prob

            if not checker in json_out["resource_level"]:
                json_out["resource_level"][checker] = {}
            for setter in merged_deps[checker]:
                if not setter in json_out["resource_level"][checker]:
                    json_out["resource_level"][checker][setter] = {}
                total_prob = 0
                for dep in merged_deps[checker][setter]:
                    key = "x-"
                    if dep.checker_res is not None:
                        key = str(dep.checker_res) + "-"
                    if dep.setter_res is not None:
                        key += str(dep.setter_res)
                    else:
                        key += "x"

                    if not key in json_out["resource_level"][checker][setter]:
                        json_out["resource_level"][checker][setter][key] = 0
                    json_out["resource_level"][checker][setter][key] += probs[dep.depvalue]
                    total_prob += probs[dep.depvalue]
                # normalize again
                for key in json_out["resource_level"][checker][setter]:
                    json_out["resource_level"][checker][setter][key] /= total_prob

        # output json
        with open(f"{self.workdir}/deps.json", "w") as f:
            f.write(json.dumps(json_out, indent=4))

    def _build_reverse_map(self, probs, merged_deps):
        """ Build and store a reverse map of dependencies. """

        # build the reverse map as well
        json_out = {"syscall_level" : {}, "resource_level" : {}}
        for checker in merged_deps:
            for setter in merged_deps[checker]:
                if not setter in json_out["syscall_level"]:
                    json_out["syscall_level"][setter] = {}

                for dep in merged_deps[checker][setter]:
                    if not checker in json_out["syscall_level"][setter]:
                        json_out["syscall_level"][setter][checker] = 0
                    json_out["syscall_level"][setter][checker] += probs[dep.depvalue]

                if not setter in json_out["resource_level"]:
                    json_out["resource_level"][setter] = {}
                if not checker in json_out["resource_level"][setter]:
                    json_out["resource_level"][setter][checker] = {}

                for dep in merged_deps[checker][setter]:
                    key = "x-"
                    if dep.setter_res is not None:
                        key = str(dep.setter_res) + "-"
                    if dep.checker_res is not None:
                        key += str(dep.checker_res)
                    else:
                        key += "x"

                    if not key in json_out["resource_level"][setter][checker]:
                        json_out["resource_level"][setter][checker][key] = 0
                    json_out["resource_level"][setter][checker][key] += probs[dep.depvalue]

        # normalize reverse map
        for setter in json_out["syscall_level"]:
            total_prob = 0
            for checker in json_out["syscall_level"][setter]:
                total_prob += json_out["syscall_level"][setter][checker]
            for checker in json_out["syscall_level"][setter]:
                json_out["syscall_level"][setter][checker] /= total_prob
        for setter in json_out["resource_level"]:
            for checker in json_out["resource_level"][setter]:
                total_prob = 0
                for key in json_out["resource_level"][setter][checker]:
                    total_prob += json_out["resource_level"][setter][checker][key]
                for key in json_out["resource_level"][setter][checker]:
                    json_out["resource_level"][setter][checker][key] /= total_prob

        # output json
        with open(f"{self.workdir}/deps_reverse.json", "w") as f:
            f.write(json.dumps(json_out, indent=4))

    def _build_arg_map(self, probs, merged_deps):
        """ Build and store a map of dependencies per argument.

        The format for the JSON is the following:
        {
            "syscall_a" : {
                "arg1" : {
                    "syscall_b" : {
                        "1" : 0.2,
                    },
                    ...
                },
                ...
            }
        }
        Syscall a is the checker, syscall b the setter.
        Other than the generic maps, syscall and resource
        level are combined here and the probabilites are
        normalized per (syscall_a, arg) pair instead of
        (syscall_a, arg, syscall_b) pair.
        """

        json_out = {}
        for checker in merged_deps:
            for setter in merged_deps[checker]:
                for dep in merged_deps[checker][setter]:
                    if not checker in json_out:
                        json_out[checker] = {}
                    arg_a = "x"
                    if dep.checker_res is not None:
                        arg_a = str(dep.checker_res)
                    if not arg_a in json_out[checker]:
                        json_out[checker][arg_a] = {}
                    if not setter in json_out[checker][arg_a]:
                        json_out[checker][arg_a][setter] = {}
                    arg_b = "x"
                    if dep.setter_res is not None:
                        arg_b = str(dep.setter_res)
                    if not arg_b in json_out[checker][arg_a][setter]:
                        json_out[checker][arg_a][setter][arg_b] = 0
                    json_out[checker][arg_a][setter][arg_b] += probs[dep.depvalue]

        # normalize
        for checker in json_out:
            for arg_a in json_out[checker]:
                total_prob = 0
                for setter in json_out[checker][arg_a]:
                    for arg_b in json_out[checker][arg_a][setter]:
                        total_prob += json_out[checker][arg_a][setter][arg_b]
                for setter in json_out[checker][arg_a]:
                    for arg_b in json_out[checker][arg_a][setter]:
                        json_out[checker][arg_a][setter][arg_b] /= total_prob

        # output json
        with open(f"{self.workdir}/deps_args.json", "w") as f:
            f.write(json.dumps(json_out, indent=4))

    def _build_arg_map_reverse(self, probs, merged_deps):
        """ Build and store a reverse map of dependencies per argument.

        The format for the JSON is the following:
        {
            "syscall_a" : {
                "arg1" : {
                    "syscall_b" : {
                        "1" : 0.2,
                    },
                    ...
                },
                ...
            }
        }
        Syscall a is the setter, syscall b the checker.
        Other than the generic maps, syscall and resource
        level are combined here and the probabilites are
        normalized per (syscall_a, arg) pair instead of
        (syscall_a, arg, syscall_b) pair.
        """

        json_out = {}
        for checker in merged_deps:
            for setter in merged_deps[checker]:
                for dep in merged_deps[checker][setter]:
                    if not setter in json_out:
                        json_out[setter] = {}
                    arg_a = "x"
                    if dep.setter_res is not None:
                        arg_a = str(dep.setter_res)
                    if not arg_a in json_out[setter]:
                        json_out[setter][arg_a] = {}
                    if not checker in json_out[setter][arg_a]:
                        json_out[setter][arg_a][checker] = {}
                    arg_b = "x"
                    if dep.checker_res is not None:
                        arg_b = str(dep.checker_res)
                    if not arg_b in json_out[setter][arg_a][checker]:
                        json_out[setter][arg_a][checker][arg_b] = 0
                    json_out[setter][arg_a][checker][arg_b] += probs[dep.depvalue]

        # normalize
        for setter in json_out:
            for arg_a in json_out[setter]:
                total_prob = 0
                for checker in json_out[setter][arg_a]:
                    for arg_b in json_out[setter][arg_a][checker]:
                        total_prob += json_out[setter][arg_a][checker][arg_b]
                for checker in json_out[setter][arg_a]:
                    for arg_b in json_out[setter][arg_a][checker]:
                        json_out[setter][arg_a][checker][arg_b] /= total_prob

        # output json
        with open(f"{self.workdir}/deps_args_reverse.json", "w") as f:
            f.write(json.dumps(json_out, indent=4))

    def _output_results_fuzzer_json(self):
        """ Output results as a JSON file for the fuzzer.

        The format for the JSON is the following:
        {
            "syscall_level" : {
                "syscall_a" : {
                    "syscall_b" : 0.2,
                    ...
                },
                ...
            },
            "resource_level" : {
                "syscall_a" : {
                    "syscall_b" : {
                        "1-1" : 0.2, # arg 1 of syscall a to arg 1 of syscall b
                        # if there is only one arg, it is x-x
                        ...
                    },
                    ...
                },
                ...
            }
        }
        """

        # merge all deps into one
        merged_deps = {}
        for api in self.apis:
            if api.deps is None:
                continue
            for checker in api.deps:
                checker_name = api.calls[checker].name
                if not checker_name in merged_deps:
                    merged_deps[checker_name] = {}
                for setter in api.deps[checker]:
                    setter_name = api.calls[setter].name
                    if not setter_name in merged_deps[checker_name]:
                        merged_deps[checker_name][setter_name] = []
                    merged_deps[checker_name][setter_name].extend(api.deps[checker][setter])

        # deduplicate
        for checker in merged_deps:
            for setter in merged_deps[checker]:
                merged_deps[checker][setter] = self._deduplicate(merged_deps[checker][setter])

        # count dependencies per dep value
        dep_count = defaultdict(int)
        for checker in merged_deps:
            for setter in merged_deps[checker]:
                for dep in merged_deps[checker][setter]:
                    dep_count[dep.depvalue] += 1

        # calculate probs
        probs_sum = 0
        for dep in dep_count:
            probs_sum += 1 / dep_count[dep]

        probs = defaultdict(float)
        for dep in dep_count:
            probs[dep] = (1 / dep_count[dep]) / probs_sum

        if self.verbose:
            print("Probabilities:")
            for p in probs:
                print(f"{p}: {probs[p]}")

        self._build_forward_map(probs, merged_deps)

        self._build_reverse_map(probs, merged_deps)

        self._build_arg_map(probs, merged_deps)

        self._build_arg_map_reverse(probs, merged_deps)

    def output_results(self):
        """ Output the results of the dependency analysis. """
        # Human readable list
        self._output_results_human_list()

        # graph with dot
        self._output_results_graph()

        # fuzzer-readable JSON
        self._output_results_fuzzer_json()


    def save_apis(self):
        """ Save the list of APIs to a file in the workdir. """

        with open(f"{self.workdir}/apis.bin", "wb") as f:
            pickle.dump(self.apis, f)

    def restore_apis(self):
        """ Restore the list of APIs from a file in the workdir. """

        if os.path.exists(f"{self.workdir}/apis.bin"):
            with open(f"{self.workdir}/apis.bin", "rb") as f:
                apis = pickle.load(f)
            not_restored = set()
            for api in self.apis:
                not_restored.add(api.to_string())
            for api in apis:
                for i in range(len(self.apis)):
                    parsed_api = self.apis[i]
                    if api.to_string() == parsed_api.to_string():
                        self.apis[i] = api
                        if parsed_api.to_string() in not_restored:
                            not_restored.remove(api.to_string())
                        break
            if len(not_restored) > 0:
                print(f"[*] Could not restore the following APIs: {not_restored}")
                sys.exit(1)

    def merge_checkpoints(self, path1, path2, path3):
        """ Merge the results of three checkpoints. """

        with open(path1, "rb") as f:
            apis1 = pickle.load(f)
        with open(path2, "rb") as f:
            apis2 = pickle.load(f)
        with open(path3, "rb") as f:
            apis3 = pickle.load(f)

        apis1.extend(apis2)
        apis1.extend(apis3)

        depCount = defaultdict(int)
        total_deps = 0
        for api in apis1:
            for i in api.deps:
                for j in api.deps[i]:
                    total_deps += len(api.deps[i][j])
                    for dep in api.deps[i][j]:
                        depCount[dep.depvalue] += 1

        with open(f"{self.workdir}/apis.bin", "wb") as f:
            pickle.dump(apis1, f)

        return depCount, total_deps

    def plot_dist(self, depCount, total_deps):
        """ Plot the distribution of dependencies. """

        dep_list = []
        for dep in depCount:
            dep_list.append((depCount[dep], dep))
        dep_list = sorted(dep_list, reverse=True)
        for dep in dep_list:
            print(f"{dep[1]}: {dep[0]}, {(1/dep[0])/total_prob}")
        print(f"Total dependencies: {total_deps}")
        x = [dep[1] for dep in dep_list]
        y = [dep[0] for dep in dep_list]
        plt.bar(x, y)
        #plt.xticks(rotation=90)
        plt.savefig(f"{self.workdir}/deps_dist.png")


    def analyze_deps(self, api):
        """ Analyze the dependencies of a single API. """

        # we extract
        # - which values do we find dependencies for?
        # - how many dependencies per value?
        # - ranking of syscalls with the most dependencies
        # - syscall with most unique dependencies
        vals = {}
        calls = {}
        indegree = {}
        outdegree = {}
        for i in api.deps:
            for j in api.deps[i]:
                if api.deps[i][j]:
                    for dep in api.deps[i][j]:
                        d = dep.depvalue
                        if not d in vals:
                            vals[d] = 0
                        vals[d] += 1
                        dependent = api.calls[i]
                        dependee = api.calls[j]
                        if not dependent.name in calls:
                            calls[dependent.name] = {}
                            calls[dependent.name]["num"] = 0
                            calls[dependent.name]["unique"] = set()
                        calls[dependent.name]["num"] += 1
                        calls[dependent.name]["unique"].add(d)
                        if not dependent.name in outdegree:
                            outdegree[dependent.name] = 0
                        outdegree[dependent.name] += 1
                        if not dependee.name in indegree:
                            indegree[dependee.name] = 0
                        indegree[dependee.name] += 1

        vals = [(vals[val], val) for val in vals]
        vals.sort(reverse=True)
        print(f"[*] Analysis for {api.to_string()}")
        print("[*] Enum values with number of dependencies in descending order:")
        for val in vals:
            print(f"{val[1]}: {val[0]}")

        calls_num = [(calls[call]["num"], call) for call in calls]
        calls_num.sort(reverse=True)
        print("[*] Calls with number of dependencies in descending order:")
        for call in calls_num:
            print(f"{call[1]}: {call[0]}")

        calls_unique = [(len(calls[call]["unique"]), call) for call in calls]
        calls_unique.sort(reverse=True)
        print("[*] Calls with number of unique dependencies in descending order:")
        for call in calls_unique:
            print(f"{call[1]}: {call[0]}")

        outdegree = [(outdegree[call], call) for call in outdegree]
        outdegree.sort(reverse=True)
        print("[*] Calls with outdegree in descending order:")
        for call in outdegree:
            print(f"{call[1]}: {call[0]}")

        indegree = [(indegree[call], call) for call in indegree]
        indegree.sort(reverse=True)
        print("[*] Calls with indegree in descending order:")
        for call in indegree:
            print(f"{call[1]}: {call[0]}")

    def analyze_deps_all(self):
        """ Analyze the dependencies of all APIs. """

        for api in self.apis:
            self.analyze_deps(api)


    def shutdown(self):
        """ Cleanup routine. """

        self.dfpr.shutdown()

    def count_deps(self):
        """ Count the number of dependencies by type. """

        depCount = defaultdict(int)
        total_deps = 0
        for api in self.apis:
            for i in api.deps:
                for j in api.deps[i]:
                    total_deps += len(api.deps[i][j])
                    for dep in api.deps[i][j]:
                        depCount[dep.depvalue] += 1
        dep_list = []
        for dep in depCount:
            dep_list.append((depCount[dep], dep))
            total_prob += 1/depCount[dep]
        dep_list = sorted(dep_list)
        for dep in dep_list:
            print(f"{dep[1]}: {dep[0]}, {(1/dep[0])/total_prob}")
        print(f"Total dependencies: {total_deps}")
        allowed_num = (2*len(dep_list))//3
        for i in range(allowed_num):
            self.multires_allowed.add(dep_list[i][1])
        self.depCount = depCount
        return total_deps

    def sample_deps(self):
        """ Print a few sample dependencies for debugging. """

        for i in self.apis[0].deps:
            for j in self.apis[0].deps[i]:
                if self.apis[0].deps[i][j]:
                    dep = self.apis[0].deps[i][j][0]
                    print(f"i {i} - {self.apis[0].calls[i].name}")
                    print(f"j {j} - {self.apis[0].calls[j].name}")
                    print(f"setter {dep.setter}")
                    print(f"sfile {dep.sfile}")
                    print(f"sline {dep.sline}")
                    print(f"checker {dep.checker}")
                    print(f"cfile {dep.cfile}")
                    print(f"cline {dep.cline}")
                    print(f"depvalue {dep.depvalue}")
                    print(f"variant {dep.variant}")
                    return
