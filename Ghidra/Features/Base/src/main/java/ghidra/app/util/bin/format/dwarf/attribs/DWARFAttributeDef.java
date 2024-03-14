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
package ghidra.app.util.bin.format.dwarf.attribs;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Function;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFAbbreviation;
import ghidra.program.model.data.LEB128;

/**
 * Information about a single DWARF attribute, as specified in a 
 * {@link DWARFAbbreviation abbreviation}.
 * <p>
 * This class handles the case where a specified attribute id is unknown to us (therefore not
 * listed in the attribute enum class), as well as the case where the form is customized with
 * an implicitValue.
 * <p>
 * Unknown forms are not supported and cause an exception.
 * 
 * @param <E> attribute id enum type
 */
public class DWARFAttributeDef<E extends Enum<E>> {

	/**
	 * Reads a {@link DWARFAttributeDef} instance from the {@link BinaryReader reader}.
	 * <p>
	 * Returns a null if its a end-of-list marker (which is only used by an attributespec list).
	 * <p>
	 * @param <E> attribute id enum type
	 * @param reader {@link BinaryReader}
	 * @param mapper func that converts an attribute id int into its enum
	 * @return DWARFAttributeDef instance, or null if EOL marker was read from the stream 
	 * @throws IOException if error reading
	 */
	public static <E extends Enum<E>> DWARFAttributeDef<E> read(BinaryReader reader,
			Function<Integer, E> mapper) throws IOException {

		int attributeId = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		int formId = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		
		if (attributeId == DWARFAttribute.EOL && formId == DWARFForm.EOL) {
			// end of attributespec list
			return null;
		}

		DWARFForm form = DWARFForm.of(formId);
		if ( form == null ) {
			throw new IOException("Unknown DWARFForm %d (0x%x)".formatted(formId, formId));
		}

		E e = mapper.apply(attributeId);

		// NOTE: implicit value is a space saving hack built into DWARF.  It adds an extra
		// field in the attributespec that needs to be read now in the .debug_abbr.  This is 
		// different than DW_FORM_indirect, which is read from the DIE in .debug_info
		long implicitValue = form == DWARFForm.DW_FORM_implicit_const // read leb128 if present 
				? reader.readNext(LEB128::signed)
				: 0;

		return new DWARFAttributeDef<>(e, attributeId, form, implicitValue);
	}

	protected final E attributeId;
	protected final DWARFForm attributeForm;
	protected final int rawAttributeId;
	protected final long implicitValue;

	public DWARFAttributeDef(E attributeId, int rawAttributeId, DWARFForm attributeForm,
			long implicitValue) {
		this.attributeId = attributeId;
		this.rawAttributeId = rawAttributeId;
		this.attributeForm = attributeForm;
		this.implicitValue = implicitValue;
	}

	/**
	 * Get the attribute id of the attribute specification.
	 * @return the attribute value
	 */
	public E getAttributeId() {
		return attributeId;
	}

	public int getRawAttributeId() {
		return rawAttributeId;
	}

	public String getAttributeName() {
		return attributeId != null
				? attributeId.name()
				: getRawAttributeIdDescription();
	}

	protected String getRawAttributeIdDescription() {
		return "unknown attribute id %d (0x%x)".formatted(rawAttributeId, rawAttributeId);
	}

	/**
	 * Get the form of the attribute specification.
	 * @return the form value
	 */
	public DWARFForm getAttributeForm() {
		return this.attributeForm;
	}

	public boolean isImplicit() {
		return attributeForm == DW_FORM_implicit_const;
	}

	public long getImplicitValue() {
		return implicitValue;
	}

	public DWARFAttributeDef<E> withForm(DWARFForm newForm) {
		return new DWARFAttributeDef<>(attributeId, rawAttributeId, newForm, implicitValue);
	}

	@Override
	public String toString() {
		return getAttributeName() + "->" + getAttributeForm();
	}

	@Override
	public int hashCode() {
		return Objects.hash(attributeForm, attributeId, implicitValue, rawAttributeId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DWARFAttributeDef)) {
			return false;
		}
		DWARFAttributeDef other = (DWARFAttributeDef) obj;
		return attributeForm == other.attributeForm &&
			Objects.equals(attributeId, other.attributeId) &&
			implicitValue == other.implicitValue && rawAttributeId == other.rawAttributeId;
	}

}
