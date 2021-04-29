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
package ghidra.program.model.lang;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.xml.*;

public class InjectPayloadJumpAssist extends InjectPayloadSleigh {

	private String baseName;

	public InjectPayloadJumpAssist(String bName, String sourceName) {
		super(sourceName);
		baseName = bName;
		type = EXECUTABLEPCODE_TYPE;
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement subel = parser.peek();
		if (subel.getName().charAt(0) == 'c') {
			name = baseName + "_index2case";
		}
		else if (subel.getName().charAt(0) == 'a') {
			name = baseName + "_index2addr";
		}
		else if (subel.getName().charAt(0) == 's') {
			name = baseName + "_calcsize";
		}
		else {
			name = baseName + "_defaultaddr";
		}
		super.restoreXml(parser, language);
	}
}
