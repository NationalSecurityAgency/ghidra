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
	
	std::wstring escaped;
	// Setting initial space; string operators will get more if needed.
	escaped.reserve(str.length() * 2);

	for (int i = 0 ; i < str.length(); ++i) {
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
