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

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.data.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.xml.*;

/**
 * A filter selecting a specific class of data-type.
 * A test of whether  data-type belongs to its class can be performed by calling
 * the filter() method.
 */
public interface DatatypeFilter {

	/**
	 * Make a copy of this filter
	 * @return the new copy
	 */
	public DatatypeFilter clone();

	/**
	 * Test if the given filter is configured and performs identically to this
	 * @param op is the given filter
	 * @return true if the two filters are equivalent
	 */
	public boolean isEquivalent(DatatypeFilter op);

	/**
	 * Test whether the given data-type belongs to this filter's data-type class
	 * @param dt is the given data-type to test
	 * @return true if the data-type is in the class, false otherwise
	 */
	public boolean filter(DataType dt);

	/**
	 * Encode this filter and its configuration to a stream
	 * @param encoder is the stream encoder
	 * @throws IOException for problems writing to the stream
	 */
	public void encode(Encoder encoder) throws IOException;

	/**
	 * Configure details of the data-type class being filtered from the given stream
	 * @param parser is the given stream decoder
	 * @throws XmlParseException if there are problems with the stream
	 */
	public void restoreXml(XmlPullParser parser) throws XmlParseException;

	/**
	 * Extract an ordered list of primitive data-types making up the given data-type
	 * 
	 * The primitive data-types are passed back in an ArrayList.  If the given data-type is already
	 * primitive, it is passed back as is. Otherwise if it is composite, its components are recursively
	 * listed. If a filler data-type is provided, it is used to fill holes in structures. If
	 * a maximum number of extracted primitives is exceeded, or if no filler is provided and a hole
	 * is encountered, or if a non-primitive non-composite data-type is encountered, false is returned.
	 * @param dt is the given data-type to extract primitives from
	 * @param max is the maximum number of primitives to extract before giving up
	 * @param filler is the data-type to use as filler (or null)
	 * @param res will hold the list of primitives
	 * @return true if all primitives were extracted
	 */
	public static boolean extractPrimitives(DataType dt, int max, DataType filler,
			ArrayList<DataType> res) {
		int metaType = PcodeDataTypeManager.getMetatype(dt);
		switch (metaType) {
			case PcodeDataTypeManager.TYPE_UNKNOWN:
			case PcodeDataTypeManager.TYPE_INT:
			case PcodeDataTypeManager.TYPE_UINT:
			case PcodeDataTypeManager.TYPE_BOOL:
			case PcodeDataTypeManager.TYPE_CODE:
			case PcodeDataTypeManager.TYPE_FLOAT:
			case PcodeDataTypeManager.TYPE_PTR:
			case PcodeDataTypeManager.TYPE_PTRREL:
				if (res.size() >= max) {
					return false;
				}
				res.add(dt);
				return true;
			case PcodeDataTypeManager.TYPE_ARRAY: {
				int numEls = ((Array) dt).getNumElements();
				DataType base = ((Array) dt).getDataType();
				for (int i = 0; i < numEls; ++i) {
					if (!extractPrimitives(base, max, filler, res)) {
						return false;
					}
				}
				return true;
			}
			case PcodeDataTypeManager.TYPE_STRUCT:
				break;
			default:
				return false;
		}
		Structure structPtr = (Structure) dt;
		int curOff = 0;
		DataTypeComponent[] components = structPtr.getDefinedComponents();
		for (DataTypeComponent component : components) {
			int nextOff = component.getOffset();
			if (nextOff > curOff) {
				if (filler == null) {
					return false;
				}
				while (curOff < nextOff) {
					if (res.size() >= max) {
						return false;
					}
					res.add(filler);
					curOff += filler.getLength();
				}
			}
			if (!extractPrimitives(component.getDataType(), max, filler, res)) {
				return false;
			}
			curOff += component.getDataType().getLength();
		}
		return true;
	}

	/**
	 * Instantiate a filter from the given stream.
	 * @param parser is the given stream decoder
	 * @return the new data-type filter instance
	 * @throws XmlParseException for problems reading the stream
	 */
	public static DatatypeFilter restoreFilterXml(XmlPullParser parser) throws XmlParseException {
		DatatypeFilter filter;
		XmlElement elemId = parser.peek();
		String nm = elemId.getAttribute(ATTRIB_NAME.name());
		if (nm.equals(SizeRestrictedFilter.NAME)) {
			filter = new SizeRestrictedFilter();
		}
		else if (nm.equals(HomogeneousAggregate.NAME_FLOAT4)) {
			filter = new HomogeneousAggregate(HomogeneousAggregate.NAME_FLOAT4,
				PcodeDataTypeManager.TYPE_FLOAT, 4, 0, 0);
		}
		else {
			// If no other name matches, assume this is a decompiler metatype
			int meta = PcodeDataTypeManager.getMetatype(nm);
			filter = new MetaTypeFilter(meta);
		}
		filter.restoreXml(parser);
		return filter;
	}
}
