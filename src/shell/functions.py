import os
import sys
import json
import pprint
import traceback

class Match(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError('No such attribute: ' + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError('No such attribute: ' + name)

class FunctionMatch(dict):
    def __init__(self, obj):
        dict.__init__(obj)
        for k, v in obj.items():
            self.__setattr__(k, v)

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError('No such attribute: ' + name)

    def __setattr__(self, name, value):
        if name == 'matches':
            self[name] = []
            for match in value:
                self[name].append(Match(match))
        else:
            self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError('No such attribute: ' + name)

class Matcher:
    def __init__(self, filename = '', function_matches = None, binaries = [], debug = 0):
        self.debug = debug
        self.binaries = []
        self.function_matches = []
        if filename and os.path.isfile(filename):
            try:
                with open(filename, 'r') as fd:
                    saved_results = json.load(fd)
                    self.binaries = saved_results['binaries']
                    for function_match in saved_results['function_matches']:
                        self.function_matches.append(FunctionMatch(function_match))                    
            except:
                traceback.print_exc()

        elif function_matches:
            self.function_matches = []
            src_basic_blocks = binaries[0].get_basic_blocks()
            target_basic_blocks = binaries[1].get_basic_blocks()            
            for function_match in function_matches.get_matches():
                function_match_data = {
                    'source': function_match.source,
                    'source_name': src_basic_blocks.get_symbol(function_match.source),
                    'target': function_match.target,
                    'target_name': target_basic_blocks.get_symbol(function_match.target),
                    'matches': []
                }

                for match in function_match.matches:
                    function_match_data['matches'].append({                     
                        'source': match.source,
                        'source_end': src_basic_blocks.get_end_address(match.source),
                        'target': match.target,
                        'target_end': target_basic_blocks.get_end_address(match.target),
                        'source_parent': match.source_parent,
                        'target_parent': match.target_parent,
                        'type': match.type,
                        'sub_type': match.sub_type,
                        'match_rate': match.match_rate,
                    })

                unidentified_blocks = self.get_unidentified_blocks(function_match, binaries, 0)
                if len(unidentified_blocks['sources']) > 0 or len(unidentified_blocks['targets']) > 0:
                    function_match_data['unidentified_blocks'] = unidentified_blocks
                self.function_matches.append(FunctionMatch(function_match_data))
            self.binaries = {
                'source': {'md5': binaries[0].get_md5()},
                'target': {'md5': binaries[1].get_md5()},
            }
        self.build_address_to_name_map()

    def get_md5(self, name):
        if name in self.binaries:
            return self.binaries[name]['md5']

        return ''

    def get_basic_blocks(self, binary, address):
        basic_blocks = {}
        function = binary.get_function_by_start_address(address)
        if function:
            for basic_block_address in function.get_basic_block_addresses():
                basic_blocks[basic_block_address] = 1
        return basic_blocks

    def get_unidentified_blocks(self, function_match, binaries, source_function_address = 0, level = 0):
        if source_function_address !=0 and source_function_address != function_match.source:
            return {}
        unidentified_blocks = {'sources': [], 'targets': []}
        src_basic_blocks = self.get_basic_blocks(binaries[0], function_match.source)
        target_basic_blocks = self.get_basic_blocks(binaries[1], function_match.target)
        for match in function_match.matches:
            if match.source in src_basic_blocks:
                del src_basic_blocks[match.source]
            if match.target in target_basic_blocks:
                del target_basic_blocks[match.target]

        if len(src_basic_blocks) > 0 or len(target_basic_blocks) > 0:
            for source in src_basic_blocks.keys():
                unidentified_blocks['sources'].append({'start': source, 'end': binaries[0].get_basic_blocks().get_end_address(source)})
            for target in target_basic_blocks.keys():
                unidentified_blocks['targets'].append({'start': target, 'end': binaries[1].get_basic_blocks().get_end_address(target)})
        return unidentified_blocks

    def get_stats(self, source_function_address = 0, level = 1):
        function_match_count = 0
        unidentified_blocks_count = {'sources': 0, 'targets': 0}
        for function_match in self.function_matches:
            if source_function_address ==0 or source_function_address == function_match.source:
                function_match_count += len(function_match.matches)
                for name in ('sources', 'targets'):
                    if name in function_match.get('unidentified_blocks', {}):
                        unidentified_blocks_count[name] += len(function_match.unidentified_blocks[name])
        return {'function_match_count': function_match_count, 'unidentified_blocks_count': unidentified_blocks_count}

    def build_address_to_name_map(self):
        self.function_names = {'source': {}, 'target': {}}
        for function_match in self.function_matches:
            self.function_names['source'][function_match.source] = function_match.source_name
            self.function_names['target'][function_match.target] = function_match.target_name
        
    def calculate_match_rates(self):
        matches = []
        for function_match in self.function_matches:
            matched_bytes = 0
            for match in function_match.matches:
                if match.source_end > match.source:
                    matched_bytes += match.source_end - match.source
                if match.target_end > match.target:
                    matched_bytes += match.target_end - match.target

            unidentified_blocks_counts = {'sources': 0, 'targets': 0}
            unidentified_blocks_bytes = {'sources': 0, 'targets': 0}

            total_unidentified_blocks_bytes = 0
            for name in unidentified_blocks_counts.keys():
                if name in function_match.get('unidentified_blocks', {}):
                    unidentified_blocks_counts[name] += len(function_match.unidentified_blocks[name])
                    for unidentified_block in function_match.unidentified_blocks[name]:
                        unidentified_blocks_bytes[name] += unidentified_block['end'] - unidentified_block['start']
                    total_unidentified_blocks_bytes += unidentified_blocks_bytes[name]

            if total_unidentified_blocks_bytes + matched_bytes > 0:
                match_rate = ((matched_bytes*100)/ (total_unidentified_blocks_bytes + matched_bytes))
            else:
                match_rate = 0

            matches.append({
                'source': function_match.source,
                'target': function_match.target,
                'function_match': function_match,
                'match_rate': match_rate
            })

            if self.debug > 0:
                print('%s (%x) - %s (%x) matches: %d matched_bytes: %d / total_unidentified_blocks_bytes (%d) / unidentified %d (%d) - %d (%d) match_rate: %d' % (
                        function_match.source_name,
                        function_match.source,
                        function_match.target_name,
                        function_match.target,
                        len(function_match.matches),
                        matched_bytes,
                        total_unidentified_blocks_bytes,
                        unidentified_blocks_bytes['sources'],
                        unidentified_blocks_counts['sources'],
                        unidentified_blocks_bytes['targets'],
                        unidentified_blocks_counts['targets'],
                        match_rate
                    )
                )

                for name in ('sources', 'targets'):
                    if not 'unidentified_blocks' in function_match or not name in function_match.unidentified_blocks:
                        continue
                    print('\t' + name)
                    for unidentified_block in function_match.unidentified_blocks[name]:
                        print('\t\t%x - %x' % (unidentified_block['start'], unidentified_block['end']))

        return matches

    def select_by_score(self):
        match_map = {}
        for match in self.calculate_match_rates():
            if not match['source'] in match_map:
                match_map[match['source']] = [match]
            else:
                match_map[match['source']].append(match)

        selected_matches = []
        for source in match_map.keys():
            if self.debug > 0:
                print('* source: %x' % source)

            maximum_score = -1
            selected_match = None
            for match in match_map[source]:
                if self.debug > 0:
                    source_name = self.function_names['source'][match['source']]
                    target_name = self.function_names['target'][match['target']]
                    print('  match.target: %x match.match_rate: %f' % (match['target'], match['match_rate']))
                    print('    %s - %s' % (source_name, target_name))

                if maximum_score < match['match_rate']:
                    maximum_score = match['match_rate']
                    selected_match = match

            if selected_match:
                selected_matches.append(selected_match['function_match'])

        return selected_matches

    def sort_matches(self, matches):
        source_to_match_map = {}
        for match in matches:
            if not match.source in source_to_match_map:
                source_to_match_map[match.source] = []
            source_to_match_map[match.source].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()

        matches = []
        for source in source_list:
            matches += source_to_match_map[source]
        return matches

    def sort(self):
        source_to_match_map = {}
        for match in self.function_matches:
            if 'matches' in match:
                match.matches = self.sort_matches(match.matches)

            if 'source_basic_blocks' in match:
                match['source_basic_blocks'].sort()

            if 'target_basic_blocks' in match:
                match['target_basic_blocks'].sort()

            if not match.source in source_to_match_map:
                source_to_match_map[match.source] = []

            source_to_match_map[match.source].append(match)

        source_list = list(source_to_match_map.keys())
        source_list.sort()
        self.function_matches = []
        for source in source_list:
            for function_match in source_to_match_map[source]:
                self.function_matches.append(FunctionMatch(function_match))

    def save(self, filename):
        try:
            with open(filename, 'w') as fd:
                json.dump({'function_matches': self.function_matches, 'binaries': self.binaries}, fd, indent = 4)
        except:
            traceback.print_exc()

if __name__ == '__main__':
    import os
    import sys
    import glob
    import argparse

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='monitor_memory')    
    parser.add_argument('-c', dest = 'command', default = 'sort')
    parser.add_argument('-d', dest = 'debug_level', default = 0, type = auto_int)
    parser.add_argument('-a', dest = 'address', default = 0x0, type = auto_int)
    parser.add_argument('filenames', metavar='FILENAMES', nargs='+', help = 'filenames')
    args = parser.parse_args()

    for filename_pattern in args.filenames:
        for filename in glob.glob(filename_pattern):
            functions_matcher = Matcher(filename = filename)
            selected_matches = functions_matcher.select_by_score()
            pprint.pprint(selected_matches)

            if args.command == 'sort':
                functions_matcher.sort()
                functions_matcher.save(filename)
