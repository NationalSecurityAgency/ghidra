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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class InjectPayloadCallfixup extends InjectPayloadSleigh {

	private List<String> targetSymbolNames;

	public InjectPayloadCallfixup(String sourceName) {
		super(sourceName);
		type = CALLFIXUP_TYPE;
		targetSymbolNames = new ArrayList<String>();
	}

	public List<String> getTargets() {
		return targetSymbolNames;
	}

	@Override
	public InjectPayloadSleigh clone() {
		InjectPayloadSleigh res = new InjectPayloadCallfixup(source);
		res.copy(this);
		return res;
	}

	@Override
	protected void copy(InjectPayloadSleigh op2) {
		super.copy(op2);
		InjectPayloadCallfixup fixup = (InjectPayloadCallfixup) op2;
		for (String target : fixup.targetSymbolNames)
			targetSymbolNames.add(target);
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement fixupEl = parser.start("callfixup");
		name = fixupEl.getAttribute("name");
		boolean pcodeSubtag = false;
		while (parser.peek().isStart()) {
			String elname = parser.peek().getName();
			if (elname.equals("target")) {
				XmlElement subel = parser.start();
				String targetName = subel.getAttribute("name");
				if (targetName == null) {
					throw new SleighException("Invalid callfixup target, missing target name");
				}
				targetSymbolNames.add(targetName);
				parser.end(subel);
			}
			else if (elname.equals("pcode")) {
				super.restoreXml(parser);
				pcodeSubtag = true;
			}
			else {
				throw new SleighException("Unknown callfixup tag: " + elname);
			}
		}
		if (!pcodeSubtag)
			throw new SleighException("<callfixup> missing <pcode> subtag: " + name);
		parser.end(fixupEl);
	}
}
