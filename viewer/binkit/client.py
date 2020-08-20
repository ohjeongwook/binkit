import os
import traceback
import glob
import json
import rpyc

class Profiles:
    def __init__(self, md5 = '*'):
        self.md5 = md5

    def list(self):
        pattern = os.path.join(os.environ['USERPROFILE'], '.binkit\\%s-*.port' % self.md5)
        profiles = []
        for filename in glob.glob(pattern):
            with open(filename, "r") as fd:
                profiles.append(json.load(fd))

        return profiles

class IDASession:
    def __init__(self, profile):
        try:
            print("Connecting to %d" % profile['port'])
            self.connection = rpyc.connect("127.0.0.1", profile['port'])
            self.connection._config['sync_request_timeout'] = 1
        except:
            self.connection = None

        if self.connection.root.get_pid() == os.getpid():
            self.connection = None

        if self.connection.root.get_md5() != profile['md5']:
            self.connection = None

    def jumpto(self, address):
        if self.connection != None:
            self.connection.root.jumpto(address)

class IDASessions:
    @staticmethod
    def connect(md5):
        profiles = Profiles(md5)
        for profile in profiles.list():
            session = IDASession(profile)
            if session.connection != None:
                return session
        return None
        
if __name__ == '__main__':
    syncer = Syncer('b8e114bf915b74e9e64aba6888c46cb6')
    syncer.jumpto(0x6C84C2A0)

    syncer = Syncer('b4be1f81a7f4521b2bc2abf72785493d')
    syncer.jumpto(0x00433392)