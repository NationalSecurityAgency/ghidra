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
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class InjectPayloadCallother extends InjectPayloadSleigh {

	/**
	 * Constructor for a partial clone of a payload whose p-code failed to parse.
	 * @param pcode is the p-code to substitute
	 * @param failedPayload is the failed callfixup
	 */
	protected InjectPayloadCallother(ConstructTpl pcode, InjectPayloadCallother failedPayload) {
		super(pcode, failedPayload);
	}

	/**
	 * Constructor for a dummy payload
	 * @param pcode is the dummy p-code to use
	 * @param nm is the name of the payload
	 */
	protected InjectPayloadCallother(ConstructTpl pcode, String nm) {
		super(pcode, CALLOTHERFIXUP_TYPE, nm);
	}

	public InjectPayloadCallother(String sourceName) {
		super(sourceName);
		type = CALLOTHERFIXUP_TYPE;
	}

	@Override
	public void saveXml(StringBuilder buffer) {
		buffer.append("<callotherfixup");
		SpecXmlUtils.encodeStringAttribute(buffer, "targetop", name);
		buffer.append(">\n");
		super.saveXml(buffer);
		buffer.append("</callotherfixup>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement fixupEl = parser.start("callotherfixup");
		name = fixupEl.getAttribute("targetop");
		if (!parser.peek().isStart() || !parser.peek().getName().equals("pcode")) {
			throw new XmlParseException("<callotherfixup> does not contain a <pcode> tag");
		}
		super.restoreXml(parser, language);
		parser.end(fixupEl);
	}
}
