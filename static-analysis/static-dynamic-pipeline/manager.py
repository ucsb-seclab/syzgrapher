import sys
import json
import pickle
import os.path
import subprocess
from collections import defaultdict

from parse_result import DynamicFuncPtrResolution, Query, LookupResult
from codeql_interf import QueryBuilder, CodeQLAPI
from worker import ResourceAPI, Dependency, Worker


class Manager:

    def __init__(self, workdir, codeqldb, input_dir,
                 query_template_dir, verbose):
        self.worker = Worker(workdir, codeqldb, input_dir,
                             query_template_dir, verbose)

    def run_full_pipeline(self):
        """ Run all required steps for a full pipeline run.

        This does not perform any post analysis.
        """

        self.worker.resolve_dynamic_calls()

        self.worker.save_apis()

        self.worker.check_dependency()

        self.worker.save_apis()

        self.worker.find_n_resolve_multi_res()

        self.worker.output_results()

    def run_and_analyze(self):
        """ Run pipeline and performs post analysis. """

        self.run_full_pipeline()

        self.worker.analyze_deps_all()

    def run_and_analyze_caching(self):
        """ Run pipeline and perform post analysis with caching. """

        self.worker.restore_apis()

        self.run_and_analyze()

        self.worker.save_apis()

    def shutdown(self):
        """ Shutdown the worker. """

        self.worker.shutdown()

    def deps_only(self):
        """ Run only dependency queries. """

        self.worker.check_dependency()

    def resolve_indirections(self):
        """ Run only indirect call resolution and save results. """

        self.worker.restore_apis()

        self.worker.resolve_dynamic_calls()

        self.worker.save_apis()

    def debug(self):
        """ Debugging function. """

        #self.worker.sample_deps()
        self.worker.restore_apis()
        self.worker.count_deps()
        self.worker.find_n_resolve_multi_res()

    def regenerate_output(self):
        """ Load saved checkpoint and regenerate the output. """

        self.worker.restore_apis()

        self.worker.output_results()

    def multi_res(self):
        """ Run the multi resolution only. """

        self.worker.restore_apis()

        self.worker.find_n_resolve_multi_res()

        self.worker.save_apis()

        self.worker.output_results()


# arguments: output of interface extraction, func pointer information, templates for queries
def main():
    if len(sys.argv) < 6:
        print("Usage: python3 manager.py <input_dir> \ \n"
              + " <query templates dir> <workdir> <codeqldb> [verbose] \n\n"
              + "The input directory is expected to contain the output of the\n"
              + "interface extraction step, the dynamical pointer information,\n"
              + "as well as the vmlinux. \n")
        sys.exit(1)

    mgr = Manager(sys.argv[3], sys.argv[4], sys.argv[1], sys.argv[2], len(sys.argv) >= 6)

    #mgr.run_and_analyze_caching()

    #mgr.debug()

    #mgr.resolve_indirections()

    #mgr.deps_only()

    #mgr.multi_res()

    mgr.shutdown()


if __name__ == "__main__":
    main()
