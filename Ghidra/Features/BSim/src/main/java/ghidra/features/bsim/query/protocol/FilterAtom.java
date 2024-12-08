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
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A single element for filtering on specific properties of ExecutableRecords or FunctionDescriptions
 * Each FilterAtom consists of a FilterTemplate describing the property to filter on, and how the filter should apply,
 * and a String -value- that the property should match (or not)
 *
 */
public class FilterAtom {
	public BSimFilterType type;			// Type of filter to perform
	public String value;				// Constant data to use in the filter

	public FilterAtom() {

	}

	public FilterAtom(BSimFilterType type, String value) {
		this.type = type;
		this.value = type.normalizeValue(value);
	}

	@Override
	public FilterAtom clone() {
		FilterAtom res = new FilterAtom();
		res.type = type;
		res.value = value;
		return res;
	}

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<atom");
		type.saveXml(fwrite);
		fwrite.append('>');
		SpecXmlUtils.xmlEscapeWriter(fwrite, value);
		fwrite.append("</atom>\n");
	}

	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("atom");
		type = BSimFilterType.nameToType(el);
		value = parser.end().getText();
		if (type.isValidValue(value)) {
			value = type.normalizeValue(value);
		}
		else {
			type = BSimFilterType.getBlank();
		}
	}

	public String getInfoString() {
		if (type.isBlank()) {
			return null;
		}
		String res = type.toString() + ' ' + value;
		return res;
	}

	/**
	 * @param rec is a specific ExecutableRecord
	 * @return true if this FilterAtom would let the specific executable pass the filter
	 */
	public boolean evaluate(ExecutableRecord rec) {
		if (value == null) {
			return true;
		}
		return type.evaluate(rec, value);
	}

	/**
	 * Returns true if this Atom has a non-null value
	 */
	public boolean isValid() {
		return value != null;
	}

	public String getValueString() {
		return value;
	}
}
