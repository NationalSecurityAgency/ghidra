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
#include <string>

std::wstring indent(size_t nSpaces) {
	return std::wstring(nSpaces, ' ');
}

std::wstring escapeXmlEntities(const std::wstring& str) {
	
	// Scan source str for problematic characters that need escaping.
	// Calculate how many characters we will need in new string.
	// The cases in this switch() statement need to match the cases in the following switch()
	// statement. 
	const size_t len = str.length();
	size_t destLen = 0;
	for (int i = 0; i < len; ++i) {
		switch (str[i]) {
		case '&':
			destLen += 5;	// length of: "&amp;"
			break;
		case '<':
		case '>':
			destLen += 4;	// length of: "&lt;" or "&gt;" 
			break;
		case '\'':
		case '"':
			destLen += 6;	// length of: "&apos;" or "&quot;"
			break;
		case 0x7F:
			break;
		default:
			destLen++;
			break;
		}
	}

	std::wstring escaped(destLen, '\0');
	for (int i = 0 ; i < len ; ++i) {
		switch (str[i]) {
			case '&' :
				escaped += L"&amp;";
				break;
			case '<' :
				escaped += L"&lt;";
				break;
			case '>' :
				escaped += L"&gt;";
				break;
			case '\'' :
				escaped += L"&apos;";
				break;
			case '"' :
				escaped += L"&quot;";
				break;
			case 0x7F :
				break;

			default :
				escaped += str[i];
				break;
		}
	}
	return escaped;
}
