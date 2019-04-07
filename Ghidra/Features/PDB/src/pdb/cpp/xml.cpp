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
#include "xml.h"

char * indent(int nSpaces) {
	switch (nSpaces) {
		case  1: return " ";
		case  2: return "  ";
		case  4: return "    ";
		case  6: return "      ";
		case  8: return "        ";
		case 10: return "          ";
		case 12: return "            ";
	}
	
	// NOTE: memory leak if following code is hit, but luckily there are no callers
	// that use indent() that would trigger this.
	// Probably would be better to throw an error if a non-standard nSpaces value is used.
	if (nSpaces < 0) {
		nSpaces = 0;
	}
	char * indent = (char *)calloc(nSpaces+1, sizeof(char));
	for (int i = 0 ; i < nSpaces ; ++i) {
		indent[i] = ' ';
	}
	return indent;
}

BSTR escapeXmlEntities(BSTR bstr) {
	WCHAR * str = (WCHAR *)bstr;
	int len = wcslen(str);
	if (len == 0) return str;
	size_t destLen = 0;
	
	// Scan source str for problematic characters that need escaping.
	// Calculate how many characters we will need in new string.
	// The cases in this switch() statement need to match the cases in the following switch()
	// statement. 
	for (int i = 0 ; i < len ; ++i) {
		switch (str[i]) {
			case '&' :
				destLen += 5;	// length of: "&amp;"
				break;
			case '<' :
			case '>' :
				destLen += 4;	// length of: "&lt;" or "&gt;" 
				break;
			case '\'' :
			case '"' :
				destLen += 6;	// length of: "&apos;" or "&quot;"
				break;
			case 0x7F :
				break;
			default :
				destLen++;
				break;
		}
	}
	
	WCHAR * newstr = (WCHAR *)calloc(destLen + 1, sizeof(WCHAR));
	WCHAR * tmp = newstr;
	
	for (int i = 0 ; i < len ; ++i) {
		switch (str[i]) {
			case '&' :
				wcscpy(tmp, L"&amp;");
				tmp += 5;
				break;
			case '<' :
				wcscpy(tmp, L"&lt;");
				tmp += 4;
				break;
			case '>' :
				wcscpy(tmp, L"&gt;");
				tmp += 4;
				break;
			case '\'' :
				wcscpy(tmp, L"&apos;");
				tmp += 6;
				break;
			case '"' :
				wcscpy(tmp, L"&quot;");
				tmp += 6;
				break;
			case 0x7F :
				break;
			default :
				*tmp = str[i];
				++tmp;
				break;
		}
	}
	
	// add null term at end of string.  Not strictly necessary since we are using calloc
	*tmp = 0;
	
	return newstr;
}
