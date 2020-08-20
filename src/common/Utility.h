#pragma once
#include <vector>
#include <string>

using namespace std;

unsigned char HexToByte(char *hexString);
vector<unsigned char> HexToBytes(char* hexString);
string BytesToHexString(vector<unsigned char> bytes);
string BytesToHexString(unsigned char* bytes, int length);