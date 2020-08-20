import os
import sys
import pprint

import cmd
import client

class BinKitShell(cmd.Cmd):
    intro = 'Welcome to the binkit shell.\n - Type help or ? to list commands.\n'
    prompt = '(binkit) '

    def do_list(self, arg):
        'List current IDA sessions'
        profiles = client.Profiles()
        self.profiles = profiles.list()
        index = 0
        
        for profile in self.profiles:
            print('%d' % index)
            print(profile)
            index += 1

    def do_export(self, arg):
        'Export IDA analysis data to a database'
        args = arg.split()
        
        index = 0
        filename = ''
        if len(args) > 0:
            index = int(args[0])
            if len(args) > 1:
                filename = args[1]            

        if index >= len(self.profiles):
            print("Index is bigger than %d" % len(self.profiles))
        else:
            print(self.profiles[index])
            if not filename:
                filename = '%s.db' % self.profiles[index]['md5']

        print(index)
        filename = os.path.abspath(filename)
        connection = client.IDASessions.connect(self.profiles[index]['md5'])
        print(connection)
        print(connection.root.export(filename))

    def do_quit(self, arg):
        'Quit shell.'
        return True

    def close(self):
        pass

def parse(arg):
    return tuple(map(int, arg.split()))

if __name__ == '__main__':
    BinKitShell().cmdloop()
