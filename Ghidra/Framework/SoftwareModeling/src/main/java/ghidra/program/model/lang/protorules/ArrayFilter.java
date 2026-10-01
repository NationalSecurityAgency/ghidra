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
import java.util.Iterator;
import java.util.Map.Entry;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class ArrayFilter extends SizeRestrictedFilter {
	private int minElements;	// Minimum number of elements in the array
	private int maxElements;	// Maximum number of elements

	public ArrayFilter() {
		super();
		minElements = 0;
		maxElements = 0;
	}

	public ArrayFilter(ArrayFilter op2) {
		super(op2);
		minElements = op2.minElements;
		maxElements = op2.maxElements;
	}

	@Override
	public DatatypeFilter clone() {
		return new ArrayFilter(this);
	}

	@Override
	public boolean isEquivalent(DatatypeFilter op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		ArrayFilter otherFilter = (ArrayFilter) op;
		if (!super.isEquivalent(otherFilter)) {
			return false;
		}
		if (minElements != otherFilter.minElements) {
			return false;
		}
		if (maxElements != otherFilter.maxElements) {
			return false;
		}
		return true;
	}

	@Override
	public boolean filter(DataType dt) {
		if (!(dt instanceof Array)) {
			return false;
		}
		if (!filterOnSize(dt)) {
			return false;
		}
		Array arr = (Array) dt;
		if (arr.getNumElements() < minElements) {
			return false;
		}
		if (maxElements != 0 && arr.getNumElements() > maxElements) {
			return false;
		}
		return true;
	}

	@Override
	protected void encodeAttributes(Encoder encoder) throws IOException {
		super.encodeAttributes(encoder);
		encoder.writeUnsignedInteger(ATTRIB_MINELEMENTS, minElements);
		encoder.writeUnsignedInteger(ATTRIB_MAXELEMENTS, maxElements);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_DATATYPE);
		encoder.writeString(ATTRIB_NAME, "array");
		encodeAttributes(encoder);
		encoder.closeElement(ELEM_DATATYPE);
	}

	@Override
	protected void restoreAttributesXml(XmlElement el) throws XmlParseException {
		super.restoreAttributesXml(el);
		Iterator<Entry<String, String>> iter = el.getAttributes().entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> attrib = iter.next();
			String nm = attrib.getKey();
			if (nm.equals(ATTRIB_MINELEMENTS.name())) {
				minElements = SpecXmlUtils.decodeInt(attrib.getValue());
			}
			else if (nm.equals(ATTRIB_MAXELEMENTS.name())) {
				maxElements = SpecXmlUtils.decodeInt(attrib.getValue());
			}
		}
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_DATATYPE.name());
		restoreAttributesXml(elem);
		parser.end(elem);
	}
}
