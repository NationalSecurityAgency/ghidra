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

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * A common base class for data-type filters that tests for a size range.
 * Any filter that inherits from this, can use ATTRIB_MINSIZE and ATTRIB_MAXSIZE
 * to place bounds on the possible sizes of data-types.  The bounds are enforced
 * by calling filterOnSize() within the inheriting classes filter() method.
 */
public class SizeRestrictedFilter implements DatatypeFilter {

	public static final String NAME = "any";

	protected int minSize;		// Minimum size of the data-type in bytes
	protected int maxSize;		// Maximum size of the data-type in bytes

	public SizeRestrictedFilter() {
		minSize = 0;
		maxSize = 0;
	}

	public SizeRestrictedFilter(int min, int max) {
		minSize = min;
		maxSize = max;
		if (maxSize == 0 && minSize >= 0) {
			// If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size
			maxSize = 0x7fffffff;
		}
	}

	/**
	 * Enforce any size bounds on a given data-type.
	 * If \b maxSize is not zero, the data-type is checked to see if its size in bytes
	 * falls between \b minSize and \b maxSize inclusive.
	 * @param dt is the data-type to test
	 * @return true if the data-type meets the size restrictions
	 */
	public boolean filterOnSize(DataType dt) {
		if (maxSize == 0) {
			return true;		// maxSize of 0 means no size filtering is performed
		}
		return (dt.getLength() >= minSize && dt.getLength() <= maxSize);
	}

	@Override
	public DatatypeFilter clone() {
		return new SizeRestrictedFilter(minSize, maxSize);
	}

	@Override
	public boolean isEquivalent(DatatypeFilter op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		SizeRestrictedFilter otherFilter = (SizeRestrictedFilter) op;
		if (maxSize != otherFilter.maxSize || minSize != otherFilter.minSize) {
			return false;
		}
		return true;
	}

	@Override
	public boolean filter(DataType dt) {
		return filterOnSize(dt);
	}

	protected void encodeAttributes(Encoder encoder) throws IOException {
		encoder.writeUnsignedInteger(ATTRIB_MINSIZE, minSize);
		encoder.writeUnsignedInteger(ATTRIB_MAXSIZE, maxSize);
	}

	protected void restoreAttributesXml(XmlElement el) {
		Iterator<Entry<String, String>> iter = el.getAttributes().entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> attrib = iter.next();
			String nm = attrib.getKey();
			if (nm.equals(ATTRIB_MINSIZE.name())) {
				minSize = SpecXmlUtils.decodeInt(attrib.getValue());
			}
			else if (nm.equals(ATTRIB_MAXSIZE.name())) {
				maxSize = SpecXmlUtils.decodeInt(attrib.getValue());
			}
		}
		if (maxSize == 0 && minSize >= 0) {
			// If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size
			maxSize = 0x7fffffff;
		}
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_DATATYPE);
		encoder.writeString(ATTRIB_NAME, NAME);
		encodeAttributes(encoder);
		encoder.closeElement(ELEM_DATATYPE);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_DATATYPE.name());
		restoreAttributesXml(elem);
		parser.end(elem);
	}
}
