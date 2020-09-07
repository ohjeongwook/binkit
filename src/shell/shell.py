import os
import sys
import time
import pprint
import json
import tempfile
import uuid
import shlex
import argparse
import cmd
import binkit

class TimeLog:
    def __init__(self):
        self.start = time.time()

    def message(self, message):
        end = time.time()
        print(message + ' (elapsed time = %f)' % (end - self.start))

class BinKitShell(cmd.Cmd):
    intro = 'Welcome to the binkit shell.\n - Type help or ? to list commands.\n'
    prompt = 'binkit> '

    def __init__(self, results_directory = 'results', log_setting_filename = 'settings.ini'):
        cmd.Cmd.__init__(self)
        self.results_directory = results_directory

        if not os.path.isdir(self.results_directory):
            try:
                os.makedirs(self.results_directory)
            except:
                pass

        self.binkit_loader = binkit.Loader(log_setting_filename)

    def do_sessions(self, arg):
        'List current IDA sessions'
        index = 0
        
        for profile in self.binkit_loader.get_profiles():
            print('# Index: %d' % index)
            for k,v in profile.items():
                print('    %s: %s' % (k, str(v)))
            index += 1
    do_s = do_sessions

    def do_export(self, arg):
        'Export IDA analysis data to a database'
        args = arg.split()
        
        index = 0
        filename = ''
        if len(args) > 0:
            index = int(args[0])
            if len(args) > 1:
                filename = args[1]            

        self.binkit_loader.export(filename)
       
    def do_load(self, arg):
        for filename in arg.split():
            time_log = TimeLog()
            self.binkit_loader.load(filename)
            time_log.message('Loaded ' + filename)

    def complete_load(self, text, line, begidx, endidx):
        print('complete_load')
        print(text)
        if not text:
            completions = [f for f in os.listdir(os.getcwd())]
        else:
            completions = [f for f in os.listdir(tex)]
        return completions

    def do_list(self, arg):
        for binary in self.binkit_loader.get_binaries():
            print(binary.get_md5())

    def do_diff(self, arg):
        parser = argparse.ArgumentParser(description='Process some integers.')
        parser.add_argument('-a', '--algorithm', dest='algorithm', default = 'init', help="Algorithm")
        parser.add_argument('-m', '--match_type', dest='match_type', default = 'CREF_FROM', help="Match Type")
        parser.add_argument('-n', '--count', dest='count', default = 1, type = int, help="Count")

        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return

        print('algorithm: %s' % args.algorithm)
        print('match_type: %s' % (args.match_type))
        print('count: %d' % args.count)

        time_log = TimeLog()
        self.binkit_loader.diff(args.algorithm, args.match_type, args.count)
        time_log.message("Diffing using %s is finished" % arg)

    def do_save(self, arg):
        self.binkit_loader.save(arg)

    def do_show(self, arg):
        filename = ''
        if arg:
            filename = os.path.abspath(arg)
        else:
            filename = os.path.join(self.results_directory, str(uuid.uuid4()) + '.json')
            self.binkit_loader.save(filename)
        self.binkit_loader.show_on_ida(filename)

    def do_quit(self, arg):
        'Quit shell.'
        return True

    def do_q(self, arg):
        'Quit shell.'
        return True

    def close(self):
        pass

def parse(arg):
    return tuple(map(int, arg.split()))

if __name__ == '__main__':
    BinKitShell().cmdloop()
