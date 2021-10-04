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

import ghidra.program.model.address.AddressSpace;

/**
 * <code>PointerTypedef</code> provides a Pointer-Typedef template datatype
 * which may be used as an alternative to {@link PointerTypedefBuilder} for
 * select use cases.  Once resolved this datatype is transformed into a 
 * standard {@link TypeDef} with appropropriate settings (see 
 * {@link TypeDefSettingsDefinition}).
 * <br>
 * NOTE: The name of this class intentionally does not end with <code>DataType</code>
 * since it does not implement a default constructor so it may not be treated
 * like other {@link BuiltIn} datatypes which are managed by the 
 * <{@link BuiltInDataTypeManager}.
 */
public class PointerTypedef extends AbstractPointerTypedefDataType {

	/**
	 * Constructs a pointer-typedef which dereferences into a specific address space.
	 * @param typeDefName name of this pointer-typedef or null to force name generation.
	 * @param referencedDataType data type this pointer-typedef points to
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 * @param space address space to be used when dereferencing pointer offset
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm, AddressSpace space) {
		super(typeDefName, referencedDataType, pointerSize, dtm);
		Objects.requireNonNull(space, "Address space must be specified");
		AddressSpaceSettingsDefinition.DEF.setValue(getDefaultSettings(), space.getName());
	}

	/**
	 * Constructs a pointer-typedef of a specific type
	 * @param typeDefName name of this pointer-typedef or null to force name generation.
	 * @param referencedDataType data type this pointer-typedef points to
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 * @param type pointer type (IBO, RELATIVE, FILE_OFFSET)
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm, PointerType type) {
		super(typeDefName, referencedDataType, pointerSize, dtm);
		Objects.requireNonNull(type, "Pointer type required");
		PointerTypeSettingsDefinition.DEF.setType(getDefaultSettings(), type);
	}

	/**
	 * Constructs a pointer-typedef without any settings
	 * @param typeDefName name of this pointer-typedef or null to force name generation.
	 * @param referencedDataType data type this pointer-typedef points to
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 */
	/* package */ PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm) {
		super(typeDefName, referencedDataType, pointerSize, dtm);
	}

	/**
	 * Constructs a pointer-typedef without any settings
	 * @param typeDefName name of this pointer-typedef or null to force name generation.
	 * @param pointerDataType associated pointer datatype
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 */
	/* package */ PointerTypedef(String typeDefName, Pointer pointerDataType, DataTypeManager dtm) {
		super(typeDefName, pointerDataType, dtm);
	}

	@Override
	public String getDescription() {
		return "Pointer-Typedef";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		Pointer ptrType = (Pointer) getDataType();
		String n = hasGeneratedNamed() ? null : getName();
		PointerTypedef td = new PointerTypedef(n, ptrType, getDataTypeManager());
		TypedefDataType.copyTypeDefSettings(this, td, false);
		return td;
	}
}
