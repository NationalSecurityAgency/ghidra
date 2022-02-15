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
package ghidra.program.model.data;

import java.util.Objects;

import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.util.InvalidNameException;

/**
 * <code>PointerTypedefBuilder</code> provides a builder for creating {@link Pointer} - {@link TypeDef}s.  
 * These special typedefs allow a modified-pointer datatype to be used for special situations where
 * a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
 * <br>
 * This builder simplifies the specification of various {@link Pointer} modifiers during the 
 * construction of an associated {@link TypeDef}.
 * <br>
 * A convenience method {@link Pointer#typedefBuilder()} also exists for creating a builder
 * from a pointer instance.  In addition the utility class {@link PointerTypedefInspector}
 * can be used to easily determine pointer-typedef settings.
 */
public class PointerTypedefBuilder {

	private PointerTypedef typedef;

	/**
	 * Construct a {@link Pointer} - {@link TypeDef} builder.
	 * @param baseDataType baseDataType or null to use a default pointer
	 * @param pointerSize pointer size or -1 to use default pointer size for specified datatype manager.
	 * @param dtm datatype manager (highly recommended although may be null)
	 */
	public PointerTypedefBuilder(DataType baseDataType, int pointerSize, DataTypeManager dtm) {
		typedef = new PointerTypedef(null, baseDataType, pointerSize, dtm);
	}

	/**
	 * Construct a {@link Pointer} - {@link TypeDef} builder.
	 * @param pointerDataType base pointer datatype (required)
	 * @param dtm datatype manager (highly recommended although may be null)
	 */
	public PointerTypedefBuilder(Pointer pointerDataType, DataTypeManager dtm) {
		Objects.requireNonNull(pointerDataType, "Pointer datatype required");
		typedef = new PointerTypedef(null, pointerDataType, dtm);
	}

	/**
	 * Set pointer-typedef name.  If not specified a default name will be generated based 
	 * upon the associated pointer type and the specified settings.
	 * @param name typedef name
	 * @return this builder
	 * @throws InvalidNameException if name contains unsupported characters
	 */
	public PointerTypedefBuilder name(String name) throws InvalidNameException {
		typedef.setName(name);
		return this;
	}

	/**
	 * Update pointer type.
	 * @param type pointer type
	 * @return this builder
	 */
	public PointerTypedefBuilder type(PointerType type) {
		PointerTypeSettingsDefinition.DEF.setType(typedef.getDefaultSettings(), type);
		return this;
	}

	/**
	 * Update pointer offset bit-shift when translating to an absolute memory offset.
	 * If specified, bit-shift will be applied after applying any specified bit-mask.
	 * @param shift bit-shift (right: positive, left: negative)
	 * @return this builder
	 */
	public PointerTypedefBuilder bitShift(int shift) {
		OffsetShiftSettingsDefinition.DEF.setValue(typedef.getDefaultSettings(), shift);
		return this;
	}

	/**
	 * Update pointer offset bit-mask when translating to an absolute memory offset.
	 * If specified, bit-mask will be AND-ed with stored offset prior to any 
	 * specified bit-shift.
	 * @param unsignedMask unsigned bit-mask
	 * @return this builder
	 */
	public PointerTypedefBuilder bitMask(long unsignedMask) {
		OffsetMaskSettingsDefinition.DEF.setValue(typedef.getDefaultSettings(), unsignedMask);
		return this;
	}

	/**
	 * Update pointer relative component-offset.  This setting is interpretted in two
	 * ways: 
	 * <ul>
	 * <li>The specified offset is considered to be relative to the start of the base datatype
	 * (e.g., structure).  It may refer to a component-offset within the base datatype or outside of 
	 * it.</li>
	 * <li>When pointer-typedef is initially applied to memory, an {@link OffsetReference} will be produced
	 * by subtracting the component-offset from the stored pointer offset to determine the 
	 * base-offset for the reference.  While the xref will be to the actual referenced location, the
	 * reference markup will be shown as <i>&lt;base&gt;+&lt;offset&gt;</i></li>
	 * </ul>
	 * @param offset component offset relative to a base-offset and associated base-datatype
	 * @return this builder
	 */
	public PointerTypedefBuilder componentOffset(long offset) {
		ComponentOffsetSettingsDefinition.DEF.setValue(typedef.getDefaultSettings(), offset);
		return this;
	}

	/**
	 * Update pointer referenced address space when translating to an absolute memory offset.
	 * @param space pointer referenced address space or null for default space
	 * @return this builder
	 */
	public PointerTypedefBuilder addressSpace(AddressSpace space) {
		AddressSpaceSettingsDefinition.DEF.setValue(typedef.getDefaultSettings(),
			space != null ? space.getName() : null);
		return this;
	}

	/**
	 * Update pointer referenced address space when translating to an absolute memory offset.
	 * @param spaceName pointer referenced address space or null for default space
	 * @return this builder
	 */
	public PointerTypedefBuilder addressSpace(String spaceName) {
		AddressSpaceSettingsDefinition.DEF.setValue(typedef.getDefaultSettings(), spaceName);
		return this;
	}

	/**
	 * Build pointer-typedef with specified settings.
	 * @return unresolved pointer typedef
	 */
	public TypeDef build() {
		return typedef;
	}
}
