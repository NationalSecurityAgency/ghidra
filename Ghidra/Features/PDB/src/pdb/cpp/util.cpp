/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "util.h"

void zero_out(const char * str, int len) {
	char * tmp = (char *)str;
	for (int i = 0 ; i < len ; ++i) {
		tmp[i] = '\0';
	}
}

int find_char(const char * str, char c) {
	int len = (int)strlen(str);
	for (int i = 0 ; i < len ; ++i) {
		if (str[i] == c) {
			return i;
		}
	}
	return -1;
}

/*
 * Populates a GUID using the string.
 * Returns 0 if the string represents a valid GUID.
 * Returns -1 if the string does not represent a valid GUID
 */
int atog(GUID * guid, const char * szGUID) {
	char * tmp = (char *)szGUID;
	char buff[256];
	/*****************************************/
	int index = find_char(tmp, '-');
	if (index == -1) {
		return -1;
	}
	zero_out(buff, 256);
	strncpy(buff, tmp, index);

	//the value could be too large and cause overflow. eg, "9b8c55da"
	if (strlen(buff) == 8 && buff[0] >= '8') {
		char msn = 0;//most significant nibble
		if (buff[0] >= '0' && buff[0] <= '9') {
			msn = buff[0] - '0';
		}
		else if (buff[0] >= 'A' && buff[0] <= 'F') {
			msn = buff[0] - 'A' + 10;
		}
		else if (buff[0] >= 'a' && buff[0] <= 'f') {
			msn = buff[0] - 'a' + 10;
		}
		guid->Data1 = strtol(buff+1, NULL, 16);
		guid->Data1 += (msn << 28);
	}
	else {
		guid->Data1 = strtol(buff, NULL, 16);
	}
	/*****************************************/
	tmp = tmp+index+1;
	index = find_char(tmp, '-');
	if (index == -1) {
		return -1;
	}
	zero_out(buff, 256);
	strncpy(buff, tmp, index);
	guid->Data2 = (unsigned short)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+index+1;
	index = find_char(tmp, '-');
	if (index == -1) {
		return -1;
	}
	zero_out(buff, 256);
	strncpy(buff, tmp, index);
	guid->Data3 = (unsigned short)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+index+1;
	index = find_char(tmp, '-');
	if (index == -1) {
		return -1;
	}
	zero_out(buff, 256);
	strncpy(buff, tmp, index);
	int ivalue = strtol(buff, NULL, 16);
	guid->Data4[0] = ivalue >> 8;
	guid->Data4[1] = ivalue & 0xff;
	/*****************************************/
	tmp = tmp+index+1;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[2] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+2;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[3] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+2;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[4] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+2;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[5] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+2;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[6] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	tmp = tmp+2;
	zero_out(buff, 256);
	strncpy(buff, tmp, 2);
	guid->Data4[7] = (unsigned char)strtol(buff, NULL, 16);
	/*****************************************/
	return 0;
}
