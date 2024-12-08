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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;

import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class ChildAtom extends FilterAtom {
	public String name = null;		// Name of the child function
	public String exename = null;		// Name of the executable (or library) containing the child (or null)

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<childatom");
		type.saveXml(fwrite);
		if (exename != null) {
			fwrite.append(" exe=\"");
			SpecXmlUtils.xmlEscapeWriter(fwrite, exename);
			fwrite.append('"');
		}
		fwrite.append('>');
		SpecXmlUtils.xmlEscapeWriter(fwrite, name);
		fwrite.append("</childatom>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("childatom");
		type = BSimFilterType.nameToType(el);
		value = null;
		exename = el.getAttribute("exe");
		name = parser.end(el).getText();
	}

	public FilterAtom clone() {
		ChildAtom newatom = new ChildAtom();
		newatom.type = type;
		newatom.value = value;
		newatom.name = name;
		newatom.exename = exename;
		return newatom;
	}

	public String getInfoString() {
		if (name == null)
			return null;
		String res = "Has child ";
		if (exename != null)
			res += '[' + exename + ']';
		res += name;
		return res;
	}

	@Override
	public String getValueString() {
		if (exename != null) {
			return '[' + exename + ']' + name;
		}
		return name;
	}
}
