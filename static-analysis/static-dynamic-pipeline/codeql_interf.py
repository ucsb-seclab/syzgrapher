import sys
import json
import os.path
import subprocess
from collections import defaultdict

from parse_result import LookupResult

class QueryBuilder:

    def __init__(self, template_dir):
        self.template_dir = template_dir

    def get_init_func_query(self, family):
        """ Return query to find init functions. """

        q = ("/**\n"
             + "* @name Init functions.\n"
             + "* @description Find all init functions.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/functionsxxx{family}\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import cpp\n\n"
             + "from GlobalVariable gv, ClassAggregateLiteral cal, Function f, Struct st, Field create, Field family\n"
             + "where \n"
             + "  (gv.getType().getName().matches(\"%net_proto_family\")\n"
             + "   and gv.getInitializer().getExpr() = cal\n"
             + "   and st.hasName(\"net_proto_family\")\n"
             + "   and create = st.getAField()\n"
             + "   and create.getName() = \"create\"\n"
             + "   and cal.getAFieldExpr(create).(FunctionAccess).getTarget() = f\n"
             + "   and family = st.getAField()\n"
             + "   and family.getName() = \"family\"\n"
             + f"   and cal.getAFieldExpr(family).(Literal).getValue() = [\"{family}\"]\n"
             + "  )\n"
             + "select f.getLocation(), f.getName()\n")

        return q

    def get_deref_query(self, entrypoints, key):
        """ Return query to find dereference of a function pointer. """

        with open(f"{self.template_dir}/template_indirect_calls.ql", "r") as f:
            q_end = f.read()
        q = ("/**\n"
             + "* @name Locate function pointer dereferences.\n"
             + "* @description Find all function pointer dereferences from given entry points and return struct and offset.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/functionsxxx{key}\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "predicate isInSyscall(VariableCall vc) {\n"
             + "  exists(Function f1 |\n"
             + "    f1.calls*(vc.getEnclosingFunction())\n"
             + "    and\n"
             + "    f1.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += """    ])\n}\n"""

        q += q_end

        return q

    def get_sockopt_deref_query(self, setsockopt_funcs, key, optval, prefix="set"):
        """ Return query to find dereference of a function pointer. """

        with open(f"{self.template_dir}/template_indirect_calls_opt.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Locate function pointer dereferences.\n"
             + "* @description Find all function pointer dereferences from given entry points and return struct and offset.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/{pref}optfunctionsxxx{key}\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "class ValidOpts extends int {\n"
             + f"    ValidOpts() {{ this = {optval} }}\n"
             + "     int getvalue() { result = this }\n}\n\n"
             + "predicate relevantStatement(Stmt s, ValidOpts a) {\n"
             + "  exists(Function f |\n"
             + "    f.getName() in [")
        for f in setsockopt_funcs:
            q += f"\"{f}\", "
        q = q[:-2]
        q += "]\n"

        q += q_end

        return q

    def get_ioctl_deref_query(self, entrypoints, key, ioctl_cmd):
        """ Return query to find dereference of a function pointer. """

        with open(f"{self.template_dir}/template_indirect_calls_ioctl.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Locate function pointer dereferences.\n"
             + "* @description Find all function pointer dereferences from given entry points and return struct and offset.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/ioctlfunctionsxxx{key}\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "class ValidOpts extends string {\n"
             + f"    ValidOpts() {{ this = \"{ioctl_cmd}\" }}\n"
             + "     string getvalue() { result = this }\n}\n\n"
             + "     predicate checkCase(SwitchCase sc) {{ \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }}\n}\n\n"
             + "predicate relevantStatement(Stmt s, ValidOpts a) {\n"
             + "  exists(Function f |\n"
             + "    f.getName() in [")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += "]\n"

        q += q_end

        return q


    def get_assign_deps_query(self, entrypoints):
        """ Return query to find dependencies based on assignments. """

        with open(f"{self.template_dir}/template_dependency1.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Assigns.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + "* @id cpp/dependentassignmentsxxxae\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import cpp\n\n"
             + "predicate isValidEntrypoint(Function f) {\n"
             + "  f.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += """]\n}\n"""

        q += ("predicate ifIsInSyscall2(IfStmt ifs) {\n"
               + "  ifs.getEnclosingFunction().getName() = [\n")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += ("]\n"
             + "  or\n"
             + "  exists(Function f1 |\n"
             + "    f1.calls*(ifs.getEnclosingFunction())\n"
             + "    and\n"
             + "    f1.getName() = [\n")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += """])\n}\n\n"""

        q += q_end

        return q

    def get_setter_deps_query(self, entrypoints):
        """ Return query to find dependencies based on setters. """

        with open(f"{self.template_dir}/template_dependency2.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + "* @id cpp/dependentsettersxxxfc\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import cpp\n\n"
             + "predicate isValidEntrypoint(Function f) {\n"
             + "  f.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += """]\n}\n"""

        q += ("predicate ifIsInSyscall2(IfStmt ifs) {\n"
               + "  ifs.getEnclosingFunction().getName() = [\n")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += ("]\n"
             + "  or\n"
             + "  exists(Function f1 |\n"
             + "    f1.calls*(ifs.getEnclosingFunction())\n"
             + "    and\n"
             + "    f1.getName() = [\n")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += "])\n}\n\n"

        q += q_end

        return q

    def get_setter_deps_int_query(self, entrypoints):
        """ Return query to find dependencies based on int setters. """

        with open(f"{self.template_dir}/template_dep_fc_int.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters int.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + "* @id cpp/dependentsettersxxxfcint\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import cpp\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n\n"
             + "predicate isValidEntrypoint(Function f) {\n"
             + "  f.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        if len(entrypoints) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += """]\n}\n"""

        q += q_end

        return q

    def get_assign_deps_int_query(self, entrypoints):
        """ Return query to find dependencies based on int assignments. """

        with open(f"{self.template_dir}/template_dep_ae_int.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Assigns int.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + "* @id cpp/dependentassignmentsxxxaeint\n"
             + "*/\n\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import cpp\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n\n"
             + "predicate isValidEntrypoint(Function f) {\n"
             + "  f.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        if len(entrypoints) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += """]\n}\n"""

        q += q_end

        return q

    def _get_setter_deps_sso_helper(self, entrypoints, opts, setsockopt_funcs, ioctl=False):
        """ Return common parts of query for setsockopt dependencies.

        See get_setter_deps_sso_x for argument definitions.
        """
        q = ("import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n\n"
             + "predicate isValidEntrypoint(Function f) {\n"
             + "  f.getName() = [")
        for f in entrypoints:
            q += f"\"{f}\", "
        q = q[:-2]
        q += """]\n}\n"""

        q += ("class ValidOpts extends string {\n"
             + "  ValidOpts() { this in [")
        for o in opts:
            q += f"\"{o}\", "
        if len(opts) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  string getvalue() { result = this }\n")
        if ioctl:
            q += "  predicate checkCase(SwitchCase sc) { \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }"
        else:
            q += "  predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
        q += "}\n\n"

        q += ("predicate checkEntryFunction(Function f) {\n"
              + f"  f.getName() in [")
        for s in setsockopt_funcs:
            q += f"\"{s}\", "
        if len(setsockopt_funcs) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += "]\n"
        q += "}\n\n"

        return q

    def get_setter_deps_ioctl_fc(self, entrypoints, ioctl_cmds, ioctl_entrypoints, ind, int_variant=False):
        """ Return query to find dependencies for ioctl.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - ioctl_cmds: list of ioctl commands
         - ioctl_entrypoints: list of entrypoints for ioctl
        This is the query where the function calls (=setters) are in the ioctl syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_opt1_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_opt1.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt1.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The first function is part of ioctl\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsetters{ind}xxxoptfcioctlint\n"
        else:
            q += f"* @id cpp/dependentsetters{ind}xxxoptfcioctl\n"
        q += ("*/\n\n"
             + self._get_setter_deps_sso_helper(entrypoints, ioctl_cmds, ioctl_entrypoints, ioctl=True))
        q += q_end

        return q

    def get_setter_deps_sso_fc(self, entrypoints, opts, setsockopt_funcs, suffix="set", int_variant=False):
        """ Return query to find dependencies for setsockopt.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - opts: list of valid opt vals for setsockopt
         - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        This is the query where the function calls (=setters) are in the setsockopt syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_opt1_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_opt1.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt1.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The first function is part of setsockopt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsettersxxxoptfc{suffix}int\n"
        else:
            q += f"* @id cpp/dependentsettersxxxoptfc{suffix}\n"
        q += ("*/\n\n"
             + self._get_setter_deps_sso_helper(entrypoints, opts, setsockopt_funcs))
        q += q_end

        return q

    def get_setter_deps_ioctl_ae(self, entrypoints, ioctl_cmds, ioctl_entrypoints, ind, int_variant=False):
        """ Return query to find dependencies for ioctl.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - ioctl_cmds: list of ioctl commands
         - ioctl_entrypoints: list of entrypoints for ioctl
        This is the query where the assign expressions (=setters) are in the ioctl syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_ae_opt1_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_ae_opt1.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt1.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The first function is part of ioctl\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsetters{ind}xxxoptaeioctlint\n"
        else:
            q += f"* @id cpp/dependentsetters{ind}xxxoptaeioctl\n"
        q += ("*/\n\n"
              + self._get_setter_deps_sso_helper(entrypoints, ioctl_cmds, ioctl_entrypoints, ioctl=True))
        q += q_end

        return q

    def get_setter_deps_sso_ae(self, entrypoints, opts, setsockopt_funcs, suffix="set", int_variant=False):
        """ Return query to find dependencies for setsockopt.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - opts: list of valid opt vals for setsockopt
         - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        This is the query where the assign expressions (=setters) are in the setsockopt syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_ae_opt1_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_ae_opt1.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt1.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The first function is part of setsockopt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsettersxxxoptae{suffix}int\n"
        else:
            q += f"* @id cpp/dependentsettersxxxoptae{suffix}\n"
        q += ("*/\n\n"
              + self._get_setter_deps_sso_helper(entrypoints, opts, setsockopt_funcs))
        q += q_end

        return q


    def get_setter_deps_ioctl_if(self, entrypoints, ioctl_cmds, ioctl_entrypoints, ind, int_variant=False):
        """ Return query to find dependencies for ioctl.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - ioctl_cmds: list of ioctl commands
         - ioctl_entrypoints: list of entrypoints for ioctl
        This is the query where the if statements are in the ioctl syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_opt2_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_opt2.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt2.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The second function is part of ioctl\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsetters{ind}xxxoptifioctlint\n"
        else:
            q += f"* @id cpp/dependentsetters{ind}xxxoptifioctl\n"
        q += ("*/\n\n"
             + self._get_setter_deps_sso_helper(entrypoints, ioctl_cmds, ioctl_entrypoints, ioctl=True))
        q += q_end

        return q

    def get_setter_deps_sso_if(self, entrypoints, opts, setsockopt_funcs, suffix="set", int_variant=False):
        """ Return query to find dependencies for setsockopt.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - opts: list of valid opt vals for setsockopt
         - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        This is the query where the if statements are in the setsockopt syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_opt2_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_opt2.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt2.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The second function is part of setsockopt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsettersxxxoptif{suffix}int\n"
        else:
            q += f"* @id cpp/dependentsettersxxxoptif{suffix}\n"
        q += ("*/\n\n"
             + self._get_setter_deps_sso_helper(entrypoints, opts, setsockopt_funcs))
        q += q_end

        return q

    def get_setter_deps_ioctl_if_ae(self, entrypoints, ioctl_cmds, ioctl_entrypoints, ind, int_variant=False):
        """ Return query to find dependencies for ioctl.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - ioctl_cmds: list of ioctl commands
         - ioctl_entrypoints: list of entrypoints for ioctl
        This is the query where the if statements are in the ioctl syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_ae_opt2_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_ae_opt2.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt2.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The second function is part of ioctl\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsetters{ind}xxxoptifioctlaeint\n"
        else:
            q += f"* @id cpp/dependentsetters{ind}xxxoptifioctlae\n"
        q += ("*/\n\n"
              + self._get_setter_deps_sso_helper(entrypoints, ioctl_cmds, ioctl_entrypoints, ioctl=True))
        q += q_end

        return q

    def get_setter_deps_sso_if_ae(self, entrypoints, opts, setsockopt_funcs, suffix="set", int_variant=False):
        """ Return query to find dependencies for setsockopt.

        Args:
         - entrypoints: list of entrypoints for all other syscalls
         - opts: list of valid opt vals for setsockopt
         - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        This is the query where the if statements are in the setsockopt syscall.
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_ae_opt2_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_ae_opt2.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters opt2.\n"
             + "* @description Pairs of functions, where the first funciton should be called before the second one. The second function is part of setsockopt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += f"* @id cpp/dependentsettersxxxoptif{suffix}aeint\n"
        else:
            q += f"* @id cpp/dependentsettersxxxoptif{suffix}ae\n"
        q += ("*/\n\n"
              + self._get_setter_deps_sso_helper(entrypoints, opts, setsockopt_funcs))
        q += q_end

        return q


    def get_setter_deps_sso_square(self, opts_fc, opts_if, entrypoints,
                                   ioctl_cmds, ioctl_entrypoints, int_variant=False):
        """ Return query to find dependencies between opts of setsockopt.

        Args:
        - opts_fc: list of valid opt vals for the setter
        - opts_if: list of valid opt vals for the if statement
        - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_opt_square_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_opt_square.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters square.\n"
             + "* @description Pairs of functions, where the first function should be called before the second one. both functions are in a setsockopt opt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += "* @id cpp/dependentsettersxxxoptsqint\n"
        else:
            q += "* @id cpp/dependentsettersxxxoptsq\n"
        q += ("*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n\n"
             + "abstract class ValidOpts extends string {\n"
             + "  bindingset[this]\n"
             + "  ValidOpts() { any() }\n"
             + "  abstract string getvalue();\n"
             + "  abstract string getkind();\n"
             + "  abstract predicate checkCase(SwitchCase sc);\n"
             + "}\n\n"
             + "abstract class ValidOptsFc extends ValidOpts {\n"
             + "  bindingset[this]\n"
             + "  ValidOptsFc() { any() }\n"
             + "}\n\n"
             + "abstract class ValidOptsIf extends ValidOpts {\n"
             + "  bindingset[this]\n"
             + "  ValidOptsIf() { any() }\n"
             + "}\n\n"
             + "class ValidOptsFcSet extends ValidOptsFc {\n"
             + "  ValidOptsFcSet() { this in [")
        for o in opts_fc['setsockopt']:
            q += f"\"{o}\", "
        if len(opts_fc['setsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"setsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsIfSet extends ValidOptsIf {\n"
              + "  ValidOptsIfSet() { this in [")
        for o in opts_if['setsockopt']:
            q += f"\"{o}\", "
        if len(opts_if['setsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"setsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsFcGet extends ValidOptsFc {\n"
              + "  ValidOptsFcGet() { this in [")
        for o in opts_fc['getsockopt']:
            q += f"\"{o}\", "
        if len(opts_fc['getsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"getsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsIfGet extends ValidOptsIf {\n"
              + "  ValidOptsIfGet() { this in [")
        for o in opts_if['getsockopt']:
            q += f"\"{o}\", "
        if len(opts_if['getsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"getsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsFcIoctl extends ValidOptsFc {\n"
              + "  ValidOptsFcIoctl() { this in [")
        for o in ioctl_cmds:
            q += f"\"{o}\", "
        if len(ioctl_cmds) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"ioctl\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }\n"
              + "}\n\n"
              + "class ValidOptsIfIoctl extends ValidOptsIf {\n"
              + "  ValidOptsIfIoctl() { this in [")
        for o in ioctl_cmds:
            q += f"\"{o}\", "
        if len(ioctl_cmds) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"ioctl\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }\n"
              + "}\n\n")

        q += ("predicate checkEntryFunction(Function f) {\n"
              + f"  f.getName() in [")
        for e in entrypoints['setsockopt']:
            q += f"\"{e}\", "
        for e in entrypoints['getsockopt']:
            q += f"\"{e}\", "
        for e in ioctl_entrypoints:
            q += f"\"{e}\", "

        if len(entrypoints['setsockopt']) + len(entrypoints['getsockopt']) + len(ioctl_entrypoints) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += "]}\n"


        q += q_end

        return q

    def get_setter_deps_sso_square_ae(self, opts_fc, opts_if, entrypoints,
                                   ioctl_cmds, ioctl_entrypoints, int_variant=False):
        """ Return query to find dependencies between opts of setsockopt.

        Args:
        - opts_fc: list of valid opt vals for the setter
        - opts_if: list of valid opt vals for the if statement
        - setsockopt_func: list of names of setsockopt functions, e.g. do_tcp_setsockopt
        """

        if int_variant:
            with open(f"{self.template_dir}/template_dependency_ae_opt_square_int.ql", "r") as f:
                q_end = f.read()
        else:
            with open(f"{self.template_dir}/template_dependency_ae_opt_square.ql", "r") as f:
                q_end = f.read()

        q = ("/**\n"
             + "* @name Dependent functions - Setters square.\n"
             + "* @description Pairs of functions, where the first function should be called before the second one. both functions are in a setsockopt opt\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n")
        if int_variant:
            q += "* @id cpp/dependentsettersxxxoptsqaeint\n"
        else:
            q += "* @id cpp/dependentsettersxxxoptsqae\n"
        q += ("*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n\n"
             + "abstract class ValidOpts extends string {\n"
             + "  bindingset[this]\n"
             + "  ValidOpts() { any() }\n"
             + "  abstract string getvalue();\n"
             + "  abstract string getkind();\n"
             + "  abstract predicate checkCase(SwitchCase sc);\n"
             + "}\n\n"
             + "abstract class ValidOptsAe extends ValidOpts {\n"
             + "  bindingset[this]\n"
             + "  ValidOptsAe() { any() }\n"
             + "}\n\n"
             + "abstract class ValidOptsIf extends ValidOpts {\n"
             + "  bindingset[this]\n"
             + "  ValidOptsIf() { any() }\n"
             + "}\n\n"
             + "class ValidOptsAeSet extends ValidOptsAe {\n"
             + "  ValidOptsAeSet() { this in [")
        for o in opts_fc['setsockopt']:
            q += f"\"{o}\", "
        if len(opts_fc['setsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"setsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsIfSet extends ValidOptsIf {\n"
              + "  ValidOptsIfSet() { this in [")
        for o in opts_if['setsockopt']:
            q += f"\"{o}\", "
        if len(opts_if['setsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"setsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsAeGet extends ValidOptsAe {\n"
              + "  ValidOptsAeGet() { this in [")
        for o in opts_fc['getsockopt']:
            q += f"\"{o}\", "
        if len(opts_fc['getsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"getsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsIfGet extends ValidOptsIf {\n"
              + "  ValidOptsIfGet() { this in [")
        for o in opts_if['getsockopt']:
            q += f"\"{o}\", "
        if len(opts_if['getsockopt']) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"getsockopt\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { sc.getExpr().(Literal).getValue() = this }\n"
              + "}\n\n"
              + "class ValidOptsAeIoctl extends ValidOptsAe {\n"
              + "  ValidOptsAeIoctl() { this in [")
        for o in ioctl_cmds:
            q += f"\"{o}\", "
        if len(ioctl_cmds) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"ioctl\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }\n"
              + "}\n\n"
              + "class ValidOptsIfIoctl extends ValidOptsIf {\n"
              + "  ValidOptsIfIoctl() { this in [")
        for o in ioctl_cmds:
            q += f"\"{o}\", "
        if len(ioctl_cmds) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += ("]}\n"
              + "  override string getvalue() { result = this }\n"
              + "  override string getkind() { result = \"ioctl\" }\n"
              + "  override predicate checkCase(SwitchCase sc) { \"\" + getType(sc) + \",\" + getDir(sc) + \",\" + getNR(sc) = this }\n"
              + "}\n\n")


        q += ("predicate checkEntryFunction(Function f) {\n"
              + f"  f.getName() in [")
        for e in entrypoints['setsockopt']:
            q += f"\"{e}\", "
        for e in entrypoints['getsockopt']:
            q += f"\"{e}\", "
        for e in ioctl_entrypoints:
            q += f"\"{e}\", "

        if len(entrypoints['setsockopt']) + len(entrypoints['getsockopt']) + len(ioctl_entrypoints) > 0:
            q = q[:-2]
        else:
            q += "\"none\""
        q += "]}\n"


        q += q_end

        return q

    def get_targetLookup_pred(self, lookupResults):
        """ Creates the targetLookup predicate given a list of LookupResult objs. """

        q = "Function targetLookup(Struct st, Field fi, Function f){\n"
        added = False
        for l in lookupResults:
            for func in l.functions:
                q += f"  (st.getName() = \"{l.query.struct}\" and st.getAField() = fi and"
                q += f" fi.getByteOffset() = {l.query.offset} and f.getName() = \"{func}\" and result = f)\n"
                q += "  or\n"
                added = True
        if not added:
            q += "  f.getName() = \"a\" and f.getName() = \"b\" and st.getName() = \"b\" and fi.getName() = \"a\" and result = f\n"
        else:
            q = q[:-5]
        q += "}\n\n"

        return q

    def get_multi_res_ae_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints an assignment. """

        with open(f"{self.template_dir}/template_multi_res_ae.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource ae.\n"
             + "* @description Find assign statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxae{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(AssignExpr ae |\n"
             + "      node.asExpr().getParent*() = ae\n"
             + "      and\n"
             + f"      ae.getRValue().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      ae.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      ae.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + ae.getLocation().getFile().toString()"
              + " + \" | \" + ae.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q

    def get_multi_res_ae_int_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints an assignment. """

        with open(f"{self.template_dir}/template_multi_res_ae.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource ae.\n"
             + "* @description Find assign statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxae{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(AssignExpr ae |\n"
             + "      node.asExpr().getParent*() = ae\n"
             #+ "      and\n"
             #+ f"      ae.getRValue().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      ae.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      ae.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + ae.getLocation().getFile().toString()"
              + " + \" | \" + ae.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q

    def get_multi_res_if_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints an if. """

        with open(f"{self.template_dir}/template_multi_res_if.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource if.\n"
             + "* @description Find if statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxif{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(IfStmt ifs |\n"
             + "      node.asExpr().getParent*() = ifs\n"
             + "      and\n"
             + f"      node.asExpr().getParent*().(NEExpr).getRightOperand().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      ifs.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      ifs.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + ifs.getLocation().getFile().toString()"
              + " + \" | \" + ifs.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q

    def get_multi_res_if_int_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints an if. """

        with open(f"{self.template_dir}/template_multi_res_if.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource if.\n"
             + "* @description Find if statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxif{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(IfStmt ifs |\n"
             + "      node.asExpr().getParent*() = ifs\n"
             #+ "      and\n"
             #+ f"      node.asExpr().getParent*().(NEExpr).getRightOperand().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      ifs.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      ifs.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + ifs.getLocation().getFile().toString()"
              + " + \" | \" + ifs.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q

    def get_multi_res_fc_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints a function call. """

        with open(f"{self.template_dir}/template_multi_res_fc.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource fc.\n"
             + "* @description Find fc statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxfc{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(FunctionCall fc |\n"
             + "      node.asExpr().getParent*() = fc\n"
             + "      and\n"
             + f"      fc.getAnArgument().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      fc.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      fc.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + fc.getLocation().getFile().toString()"
              + " + \" | \" + fc.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q

    def get_multi_res_fc_int_query(self, target_lookup, file, line, val,
                               syscall_entry, key, syscall_id):
        """ Return query to find syscall argument that taints a function call. """

        with open(f"{self.template_dir}/template_multi_res_fc.ql", "r") as f:
            q_end = f.read()

        q = ("/**\n"
             + "* @name Multi resource fc.\n"
             + "* @description Find fc statements that might depend on multiple resources.\n"
             + "* @kind problem\n"
             + "* @problem.severity recommendation\n"
             + f"* @id cpp/multiresxxxfc{key}\n"
             + "*/\n\n"
             + "import cpp\n"
             + "import semmle.code.cpp.stmts.Stmt\n"
             + "import semmle.code.cpp.controlflow.Guards\n"
             + "import semmle.code.cpp.pointsto.CallGraph\n"
             + "import semmle.code.cpp.dataflow.new.DataFlow\n"
             + "import semmle.code.cpp.dataflow.new.TaintTracking\n\n"
             + target_lookup
             + "Function getTarget(VariableCall vc) {\n"
             + "  exists(Function f, Struct st |\n"
             + "    st.getAField() = vc.getExpr().(PointerFieldAccess).getTarget()\n"
             + "    and\n"
             + "    result = targetLookup(st, vc.getExpr().(PointerFieldAccess).getTarget(), f)\n"
             + "    )\n"
             + "}\n\n"
             + "module IndirectFunctionCallConfiguration implements DataFlow::ConfigSig {\n"
             + "  predicate isSource(DataFlow::Node node) {\n"
             + f"    node.asParameter().getFunction().getName() = \"{syscall_entry}\"\n"
             + "  }\n\n"
             + "  predicate isSink(DataFlow::Node node) {\n"
             + "    exists(FunctionCall fc |\n"
             + "      node.asExpr().getParent*() = fc\n"
             #+ "      and\n"
             #+ f"      fc.getAnArgument().(EnumConstantAccess).toString() = \"{val}\"\n"
             + "      and\n"
             + f"      fc.getLocation().getFile().toString() = \"{file}\"\n"
             + "      and\n"
             + f"      fc.getLocation().getStartLine() = {line})\n"
             + "  }\n")

        q += q_end

        q += ("select sink, i.toString() + \" | \" + fc.getLocation().getFile().toString()"
              + " + \" | \" + fc.getLocation().getStartLine()"
              + f" + \" | {val} | {syscall_id}\"\n")

        return q


class CodeQLAPI:

    def __init__(self, workdir, codeqldb, verbose):
        self.db = codeqldb
        self.workdir = workdir
        self.verbose = verbose

    def _add_codeql_query(self, q, key):
        """ Stage query for execution during the next _run_all_queries call. """

        with open(f"{self.workdir}/codeql/queries{key}.ql", "a") as f:
            f.write(q)

    def _run_all_queries(self, big=False, debug=False):
        """ Execute all staged queries. """

        cmd = [
            "codeql", "database", "analyze", self.db,
            f"{self.workdir}/codeql/", "--format=sarif-latest",
            "--rerun", f"--output={self.workdir}/test.sarif",
            "--threads=32", "--max-disk-cache=102400"
        ]
        if big:
            cmd.append("--ram=63000")

        if debug:
            with open(f"{self.workdir}/multi_res_tcp_ipv4.sarif", "r") as f:
                data = f.read()
        else:
            if self.verbose:
                print(f"[*]Running CodeQL query: {' '.join(cmd)}")
                p = subprocess.Popen(cmd, shell=False)
                p.communicate()
            else:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if p.returncode != 0:
                print("Error: CodeQL analyze failed")
                if not self.verbose:
                    print(p.stderr.decode("utf-8"))
                sys.exit(1)

            with open(f"{self.workdir}/test.sarif", "r") as f:
                data = f.read()

        query_results = json.loads(data)
        results = defaultdict(list)
        for res in query_results['runs'][0]['results']:
            t = res['message']['text']
            t_splitted = t.split("\n")
            key = res['ruleId'].split("xxx")[1]
            #results[key].append({'struct': struct, 'offset': offset, 'fc': "function" in res['ruleId']})
            for ts in t_splitted:
                results[key].append({'message': ts})
        return results

    def _run_codeql_query(self, q):
        """ Execute CodeQL query on the database. """

        with open(f"{self.workdir}/last_query.ql", "w") as f:
            f.write(q)
        with open(f"{self.query_template_dir}/XXX_syzgrapher_static_dynamic_ping_pong_XXX.ql", "w") as f:
            f.write(q)
        cmd = [
            "codeql", "database", "analyze", self.db,
            f"{self.query_template_dir}/XXX_syzgrapher_static_dynamic_ping_pong_XXX.ql", "--format=sarif-latest",
            "--rerun", f"--output={self.workdir}/test.sarif"
        ]
        if self.verbose:
            print(f"[*]Running CodeQL query: {' '.join(cmd)}")
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            print("Error: CodeQL query failed")
            print(p.stderr.decode("utf-8"))
            sys.exit(1)


    def _retrieve_codeql_results(self):
        """ Retrieve list of function pointers to be resolved.

        This function only works in combination with _run_codeql_query.
        Returns a list with elements of the form {'struct': 's', 'offset': 1}.
        """

        with open(f"{self.workdir}/test.sarif", "r") as f:
            data = f.read()
        query_results = json.loads(data)

        results = []
        for res in query_results['runs'][0]['results']:
            t = res['message']['text']
            t = t.split("|")
            struct = t[0].strip()
            offset = int(t[1].strip())
            results.append({'struct': struct, 'offset': offset})
        if self.verbose:
            print(f"[*]Retrieved {len(results)} function pointers to resolve")
            print(results)
        return results

    def _cleanup_codeql_dir(self):
        """ Remove all query in the codeql directory. """

        for f in os.listdir(f"{self.workdir}/codeql"):
            if f.endswith(".ql"):
                os.remove(f"{self.workdir}/codeql/{f}")

    def _cleanup_database_cache(self):
        """ Removes cached information from the database. """

        p = subprocess.run(["codeql", "database", "cleanup", "-m", "clear", self.db],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            print("Error: CodeQL database cleanup failed")
            print(p.stderr.decode("utf-8"))
            sys.exit(1)
