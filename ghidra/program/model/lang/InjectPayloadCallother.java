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

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class InjectPayloadCallother extends InjectPayloadSleigh {

	public InjectPayloadCallother(String sourceName) {
		super(sourceName);
		type = CALLOTHERFIXUP_TYPE;
	}

	@Override
	public InjectPayloadSleigh clone() {
		InjectPayloadSleigh res = new InjectPayloadCallother(source);
		res.copy(this);
		return res;
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement fixupEl = parser.start("callotherfixup");
		name = fixupEl.getAttribute("targetop");
		if (!parser.peek().isStart() || !parser.peek().getName().equals("pcode"))
			throw new SleighException("<callotherfixup> does not contain a <pcode> tag");
		super.restoreXml(parser);
		parser.end(fixupEl);
	}
}
