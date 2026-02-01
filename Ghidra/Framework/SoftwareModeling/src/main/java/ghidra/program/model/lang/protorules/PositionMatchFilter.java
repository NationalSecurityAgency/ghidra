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

import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Filter that selects for a particular parameter position.
 * This matches if the position of the current parameter being assigned, within the data-type
 * list, matches the position attribute of this filter.
 */
public class PositionMatchFilter implements QualifierFilter {

	private int position;		// Parameter position being filtered for

	public PositionMatchFilter(int pos) {
		position = pos;
	}

	@Override
	public QualifierFilter clone() {
		return new PositionMatchFilter(position);
	}

	@Override
	public boolean isEquivalent(QualifierFilter op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		PositionMatchFilter otherFilter = (PositionMatchFilter) op;
		if (position != otherFilter.position) {
			return false;
		}
		return true;
	}

	@Override
	public boolean filter(PrototypePieces proto, int pos) {
		return (pos == position);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_POSITION);
		encoder.writeSignedInteger(ATTRIB_INDEX, position);
		encoder.closeElement(ELEM_POSITION);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_POSITION.name());
		position = SpecXmlUtils.decodeInt(elem.getAttribute(ATTRIB_INDEX.name()));
		parser.end(elem);
	}
}
