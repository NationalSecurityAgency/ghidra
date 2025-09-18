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
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Filter on a homogeneous aggregate data-type
 * All primitive data-types must be the same.
 */
public class HomogeneousAggregate extends SizeRestrictedFilter {

	public static final String NAME_FLOAT = "homogeneous-float-aggregate";
	public static final int DEFAULT_MAX_PRIMITIVES = 4;		// Maximum number of primitives in aggregate data-type
	private String name;
	private int metaType;		// The expected meta-type
	private int maxPrimitives;	// Maximum number of primitives in the aggregate

	/**
	 * Constructor for use with decode()
	 * @param nm is the name attribute associated with the tag
	 * @param meta is the expected element meta-type
	 */
	public HomogeneousAggregate(String nm, int meta) {
		name = nm;
		metaType = meta;
		maxPrimitives = DEFAULT_MAX_PRIMITIVES;
	}

	public HomogeneousAggregate(String nm, int meta, int maxPrim, int minSize, int maxSize) {
		super(minSize, maxSize);
		name = nm;
		metaType = meta;
		maxPrimitives = maxPrim;
	}

	/**
	 * Copy constructor
	 * @param op2 is the filter to copy
	 */
	public HomogeneousAggregate(HomogeneousAggregate op2) {
		super(op2);
		name = op2.name;
		metaType = op2.metaType;
		maxPrimitives = op2.maxPrimitives;
	}

	@Override
	public DatatypeFilter clone() {
		return new HomogeneousAggregate(this);
	}

	@Override
	public boolean filter(DataType dt) {
		int meta = PcodeDataTypeManager.getMetatype(dt);
		if (meta != PcodeDataTypeManager.TYPE_ARRAY && meta != PcodeDataTypeManager.TYPE_STRUCT) {
			return false;
		}
		PrimitiveExtractor primitives = new PrimitiveExtractor(dt, true, 0, maxPrimitives);
		if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown() ||
			!primitives.isAligned() || primitives.containsHoles()) {
			return false;
		}
		DataType base = primitives.get(0).dt;
		int baseMeta = PcodeDataTypeManager.getMetatype(base);
		if (baseMeta != metaType) {
			return false;
		}
		for (int i = 1; i < primitives.size(); ++i) {
			if (primitives.get(i).dt != base) {
				return false;
			}
		}
		return true;
	}

	@Override
	protected void encodeAttributes(Encoder encoder) throws IOException {
		super.encodeAttributes(encoder);
		encoder.writeUnsignedInteger(ATTRIB_MAX_PRIMITIVES, maxPrimitives);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_DATATYPE);
		encoder.writeString(ATTRIB_NAME, name);
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
			if (nm.equals(ATTRIB_MAX_PRIMITIVES.name())) {
				int xmlMaxPrim = SpecXmlUtils.decodeInt(attrib.getValue());
				if (xmlMaxPrim > 0) {
					maxPrimitives = xmlMaxPrim;
				}
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
