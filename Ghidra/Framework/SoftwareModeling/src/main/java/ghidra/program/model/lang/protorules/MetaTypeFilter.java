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
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.xml.*;

/**
 * Filter on a single meta data-type. Filters on TYPE_STRUCT or TYPE_FLOAT etc.
 * Additional filtering on size of the data-type can be configured.
 */
public class MetaTypeFilter extends SizeRestrictedFilter {

	protected int metaType;	// The meta-type this filter lets through

	/**
	 * Constructor for use with decode().
	 * @param meta is the data-type metatype to filter on
	 */
	public MetaTypeFilter(int meta) {
		metaType = meta;
	}

	/**
	 * Constructor
	 * @param meta is the data-type metatype to filter on
	 * @param min is the minimum size in bytes
	 * @param max is the maximum size in bytes
	 */
	public MetaTypeFilter(int meta, int min, int max) {
		super(min, max);
		metaType = meta;
	}

	@Override
	public boolean isEquivalent(DatatypeFilter op) {
		if (!super.isEquivalent(op)) {
			return false;
		}
		if (this.getClass() != op.getClass()) {
			return false;
		}
		MetaTypeFilter otherFilter = (MetaTypeFilter) op;
		if (metaType != otherFilter.metaType) {
			return false;
		}
		return true;
	}

	@Override
	public DatatypeFilter clone() {
		return new MetaTypeFilter(metaType, minSize, maxSize);
	}

	@Override
	public boolean filter(DataType dt) {
		if (PcodeDataTypeManager.getMetatype(dt) != metaType) {
			return false;
		}
		return filterOnSize(dt);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_DATATYPE);
		String meta = PcodeDataTypeManager.getMetatypeString(metaType);
		encoder.writeString(ATTRIB_NAME, meta);
		encodeAttributes(encoder);
		encoder.closeElement(ELEM_DATATYPE);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_DATATYPE.name());
		metaType = PcodeDataTypeManager.getMetatype(elem.getAttribute(ATTRIB_NAME.name()));
		restoreAttributesXml(elem);
		parser.end(elem);
	}

}
