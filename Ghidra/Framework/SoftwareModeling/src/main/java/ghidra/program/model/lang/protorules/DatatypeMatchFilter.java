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
package ghidra.program.model.lang.protorules;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Check if the function signature has a specific data-type in a specific position.
 * This filter does not match against the data-type in the current position
 * being assigned, but against a parameter at a fixed position.
 */
public class DatatypeMatchFilter implements QualifierFilter {

	private int position;				// The position of the data-type to check
	private DatatypeFilter typeFilter;	// The data-type that must be at position

	public DatatypeMatchFilter() {
		position = -1;
		typeFilter = null;
	}

	@Override
	public QualifierFilter clone() {
		DatatypeMatchFilter res = new DatatypeMatchFilter();
		res.position = position;
		res.typeFilter = typeFilter.clone();
		return res;
	}

	@Override
	public boolean isEquivalent(QualifierFilter op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		DatatypeMatchFilter otherFilter = (DatatypeMatchFilter) op;
		if (position != otherFilter.position) {
			return false;
		}
		return typeFilter.isEquivalent(otherFilter.typeFilter);
	}

	@Override
	public boolean filter(PrototypePieces proto, int pos) {
		// The position of the current parameter being assigned, pos, is NOT used.
		DataType dt;
		if (position < 0) {
			dt = proto.outtype;
		}
		else {
			if (position >= proto.intypes.size()) {
				return false;
			}
			dt = proto.intypes.get(position);
		}
		return typeFilter.filter(dt);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_DATATYPE_AT);
		encoder.writeSignedInteger(ATTRIB_INDEX, position);
		typeFilter.encode(encoder);
		encoder.closeElement(ELEM_DATATYPE_AT);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_DATATYPE_AT.name());
		position = SpecXmlUtils.decodeInt(elem.getAttribute(ATTRIB_INDEX.name()));
		typeFilter = DatatypeFilter.restoreFilterXml(parser);
		parser.end(elem);
	}
}
