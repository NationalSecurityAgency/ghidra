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
package ghidra.app.util.bin.format.dwarf4;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;

import java.io.IOException;

/**
 * Information about a single DWARF attribute.
 */
public class DWARFAttributeSpecification {
	private final int attribute;
	private final DWARFForm attributeForm;

	/**
	 * Reads a {@link DWARFAttributeSpecification} instance from the {@link BinaryReader reader}.
	 * <p>
	 * Returns a null if its a end-of-list marker.
	 * <p>
	 * @param reader
	 * @return
	 * @throws IOException
	 */
	public static DWARFAttributeSpecification read(BinaryReader reader) throws IOException {
		int attribute = LEB128.readAsUInt32(reader);
		DWARFForm attributeForm = DWARFForm.find(LEB128.readAsUInt32(reader));

		return attribute != 0 && attributeForm != DWARFForm.NULL
				? new DWARFAttributeSpecification(attribute, attributeForm) : null;
	}

	public DWARFAttributeSpecification(int attribute, DWARFForm attributeForm) {
		this.attribute = attribute;
		this.attributeForm = attributeForm;
	}

	/**
	 * Get the attribute of the attribute specification.
	 * @return the attribute value
	 */
	public int getAttribute() {
		return this.attribute;
	}

	/**
	 * Get the form of the attribute specification.
	 * @return the form value
	 */
	public DWARFForm getAttributeForm() {
		return this.attributeForm;
	}

	@Override
	public String toString() {
		return DWARFUtil.toString(DWARFAttribute.class, getAttribute()) + "->" + getAttributeForm();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + attribute;
		result = prime * result + ((attributeForm == null) ? 0 : attributeForm.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof DWARFAttributeSpecification))
			return false;
		DWARFAttributeSpecification other = (DWARFAttributeSpecification) obj;
		if (attribute != other.attribute)
			return false;
		if (attributeForm != other.attributeForm)
			return false;
		return true;
	}
}
