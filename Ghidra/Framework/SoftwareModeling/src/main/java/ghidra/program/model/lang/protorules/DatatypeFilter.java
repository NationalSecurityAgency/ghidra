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

import ghidra.program.model.data.DataType;
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
