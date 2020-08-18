import json

class Drawer:
    def __init__(self, filename):
        with open(filename, 'r') as fd:
            self.match_results = json.load(fd)

        md5 = idc.GetInputMD5().lower()
        if md5 == self.match_results['binaries']['source']['md5']:
            self.current_mode = 'source'
        elif md5 == self.match_results['binaries']['target']['md5']:
            self.current_mode = 'target'
        else:
            self.current_mode = 'unknown'

    def color(self):
        for function_match in self.match_results['function_matches']:
            for match_data in function_match['matches']:
                start = match_data[self.current_mode]
                end = match_data[self.current_mode+'_end']
                address = start
                while address < end:
                    SetColor(address, CIC_ITEM, 0xFF0000)
                    address += ItemSize(address)

if __name__ == '__main__':
    filename = r'C:\Users\tester\Desktop\examples\test_function_control_flow_match-00000000-00000004.json'
    drawer = Drawer(filename)
    drawer.color()
