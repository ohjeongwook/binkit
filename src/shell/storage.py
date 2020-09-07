import os
import sys
import json
import pprint
import traceback

class FunctionMatchFile:
    def __init__(self, filename = '', match_results = {}, binaries = None):
        if filename and os.path.isfile(filename):
            try:
                with open(filename, 'r') as fd:
                    self.match_results = json.load(fd)
            except:
                traceback.print_exc()
        else:
            self.match_results = match_results
        self.binaries = binaries
        self.add_binary_meta_data()
        self.add_names()
        self.add_basic_block_data()

    def sort_matches(self, matches):
        source_to_match_map = {}
        for match in matches:
            if not match['source'] in source_to_match_map:
                source_to_match_map[match['source']] = []
            source_to_match_map[match['source']].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()

        matches = []
        for source in source_list:
            matches += source_to_match_map[source]
        return matches

    def sort(self):
        source_to_match_map = {}
        for match in self.match_results['function_matches']:
            if 'matches' in match:
                match['matches'] = self.sort_matches(match['matches'])

            if 'source_basic_blocks' in match:
                match['source_basic_blocks'].sort()

            if 'target_basic_blocks' in match:
                match['target_basic_blocks'].sort()

            if not match['source'] in source_to_match_map:
                source_to_match_map[match['source']] = []

            source_to_match_map[match['source']].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()
        self.match_results['function_matches'] = []
        for source in source_list:
            self.match_results['function_matches'] += source_to_match_map[source]

    def add_binary_meta_data(self):
        if not self.binaries:
            return

        self.match_results['binaries'] = {
            'source':
                {
                    'md5': self.binaries[0].get_md5()
                },
            'target':
                {
                    'md5': self.binaries[1].get_md5()
                },
        }

    def add_names(self):
        if not self.binaries:
            return

        source_basic_blocks = self.binaries[0].get_basic_blocks()
        target_basic_blocks = self.binaries[1].get_basic_blocks()

        for function_match in self.match_results['function_matches']:
            function_match['source_name'] = source_basic_blocks.get_symbol(function_match['source'])
            function_match['target_name'] = target_basic_blocks.get_symbol(function_match['target'])

    def add_basic_block_data(self):
        if not self.binaries:
            return

        source_basic_blocks = self.binaries[0].get_basic_blocks()
        target_basic_blocks = self.binaries[1].get_basic_blocks()

        for function_match in self.match_results['function_matches']:
            for basic_block_match in function_match['matches']:
                basic_block_match['source_end'] = source_basic_blocks.get_basic_block_end(basic_block_match['source'])
                basic_block_match['target_end'] = target_basic_blocks.get_basic_block_end(basic_block_match['target'])

            if 'unidentified_blocks' in function_match:
                for source in function_match['unidentified_blocks']['sources']:
                    source['end'] = source_basic_blocks.get_basic_block_end(source['start'])

                for target in function_match['unidentified_blocks']['targets']:
                    target['end'] = target_basic_blocks.get_basic_block_end(target['start'])

        print('add_basic_block_data finished')

    def save(self, filename):
        print('save ' + filename)

        try:
            with open(filename, 'w') as fd:
                json.dump(self.match_results, fd, indent = 4)
        except:
            traceback.print_exc()

class FunctionMatchTool:
    def __init__(self, function_matches, binaries = None):
        self.debug_level = 0
        self.function_matches = function_matches
        self.binaries = binaries

    def get_stats(self, source_function_address = 0, level = 1):
        function_match_count = 0
        unidentified_blocks_count = {'sources': 0, 'targets': 0}
        for function_match in self.function_matches.get_matches():
            if source_function_address !=0 and source_function_address != function_match.source:
                continue
            function_match_count += len(function_match.basic_block_match_list)
            unidentified_blocks = self.get_unidentified_blocks(function_match, source_function_address)
            for name in ('sources', 'targets'):
                if name in unidentified_blocks:
                    unidentified_blocks_count[name] += len(unidentified_blocks[name])

        return {'function_match_count': function_match_count, 'unidentified_blocks_count': unidentified_blocks_count}

    def get_match_list(self, matches, level = 1):
        prefix = '\t' * level
        match_list = []
        for match in matches:
            if self.debug_level > 0:
                print(prefix + 'Match: %x vs %x - match_rate: %d' % (match.source, match.target, match.match_rate))

            match_list.append({
                'source_parent': match.source_parent,
                'target_parent': match.target_parent,
                'source': match.source,
                'target': match.target,
                'type': match.type,
                'sub_type': match.sub_type,
                'match_rate': match.match_rate
            })

        return match_list

    def get_basic_blocks_set(self, index, address):
        basic_blocks = {}
        function = self.binaries[index].get_function(address)
        if not function:
            return
        for basic_block_address in function.get_basic_blocks():
            basic_blocks[basic_block_address] = 1
        return basic_blocks

    def get_unidentified_blocks(self, function_match, source_function_address = 0, level = 0):
        if source_function_address !=0 and source_function_address != function_match.source:
            return {}

        unidentified_blocks = {'sources': [], 'targets': []}
        src_basic_blocks = self.get_basic_blocks_set(0, function_match.source)
        target_basic_blocks = self.get_basic_blocks_set(1, function_match.target)

        for match in function_match.basic_block_match_list:
            if match.source in src_basic_blocks:
                del src_basic_blocks[match.source]

            if match.target in target_basic_blocks:
                del target_basic_blocks[match.target]

        if len(src_basic_blocks) > 0 or len(target_basic_blocks) > 0:
            for source in src_basic_blocks.keys():
                unidentified_blocks['sources'].append({'start': source})
            
            for target in target_basic_blocks.keys():
                unidentified_blocks['targets'].append({'start': target})

            if self.debug_level > 0:
                prefix = '\t' * level
                print(prefix + '%x - %x' % (function_match.source, function_match.target))
                print(prefix + '\t- src:')

                for src_basic_block in src_basic_blocks.keys():
                    print(prefix + '\t%.8x' % src_basic_block)

                print('\t- target:')
                for target_basic_block in target_basic_blocks.keys():
                    print(prefix + '\t%.8x' % target_basic_block)

        return unidentified_blocks

    def get_function_match_file(self, source_function_address = 0, level = 1):
        if self.function_matches == None:
            print("No function matches found")
            return

        prefix = '\t' * level
        function_basic_block_match_list = []
        for function_match in self.function_matches.get_matches():
            if source_function_address !=0 and source_function_address != function_match.source:
                continue
            if self.debug_level > 0:
                print(prefix + 'FunctionMatch: %x vs %x' % (function_match.source, function_match.target))
            function_basic_block_match = {'source': function_match.source, 'target': function_match.target}
            function_basic_block_match['matches'] = self.get_match_list(function_match.basic_block_match_list, level = level + 1)
            unidentified_blocks = self.get_unidentified_blocks(function_match, source_function_address)

            if len(unidentified_blocks['sources']) > 0 or len(unidentified_blocks['targets']) > 0:
                function_basic_block_match['unidentified_blocks'] = unidentified_blocks

            function_basic_block_match_list.append(function_basic_block_match)
        return FunctionMatchFile(match_results = {'function_matches': function_basic_block_match_list}, binaries = self.binaries)

if __name__ == '__main__':
    import os
    import sys
    import glob
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='monitor_memory')    
    parser.add_argument('-c', dest = "command", default = 'sort')
    parser.add_argument('-d', dest = "debug_level", default = 0, type = auto_int)
    parser.add_argument('-a', dest = "address", default = 0x0, type = auto_int)
    parser.add_argument('filenames', metavar='FILENAMES', nargs='+', help = "filenames")
    args = parser.parse_args()

    for filename_pattern in args.filenames:
        for filename in glob.glob(filename_pattern):
            function_match_file = FunctionMatchFile(filename)
            function_match_file.sort()
            function_match_file.save(filename)
