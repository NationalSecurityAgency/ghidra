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

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;

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
 * {@link BuiltInDataTypeManager}.
 * <br>
 * NOTE: As a {@link BuiltIn} datatype the use of {@link #setName(String)} and
 * {@link #setNameAndCategory(CategoryPath, String)} is disabled.  The datatype
 * instance must be instantiated with the correct typedef name.  
 */
public class PointerTypedef extends GenericDataType implements TypeDef {

	private boolean isAutoNamed;
	private TypedefDataType modelTypedef;
	private UniversalID universalId = UniversalIdGenerator.nextID();

	/**
	 * Constructs a pointer-typedef which dereferences into a specific address space.
	 * @param typeDefName name of this pointer-typedef or null to use auto-named typedef.
	 * @param referencedDataType data type this pointer-typedef points to or null
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon specified 
	 * address space and datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 * @param space address space to be used when dereferencing pointer offset
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm, AddressSpace space) {
		this(typeDefName, referencedDataType, getPreferredPointerSize(pointerSize, dtm, space),
			dtm);
		AddressSpaceSettingsDefinition.DEF.setValue(getDefaultSettings(), space.getName());
	}

	/**
	 * Constructs a pointer-typedef of a specific type
	 * @param typeDefName name of this pointer-typedef or null to use auto-named typedef.
	 * @param referencedDataType data type this pointer-typedef points to or null
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 * @param type pointer type (IBO, RELATIVE, FILE_OFFSET)
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm, PointerType type) {
		this(typeDefName, referencedDataType, pointerSize, dtm);
		Objects.requireNonNull(type, "Pointer type required");
		PointerTypeSettingsDefinition.DEF.setType(getDefaultSettings(), type);
	}

	/**
	 * Constructs a offset-pointer-typedef
	 * @param typeDefName name of this pointer-typedef or null to use auto-named typedef.
	 * @param referencedDataType data type this pointer-typedef points to or null
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 * @param componentOffset signed component offset setting value (see {@link ComponentOffsetSettingsDefinition}
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm, long componentOffset) {
		this(typeDefName, referencedDataType, pointerSize, dtm);
		ComponentOffsetSettingsDefinition.DEF.setValue(getDefaultSettings(), componentOffset);
	}

	/**
	 * Constructs a pointer-typedef without any settings
	 * @param typeDefName name of this pointer-typedef or null to use auto-named typedef.
	 * @param referencedDataType data type this pointer-typedef points to or null
	 * @param pointerSize pointer size in bytes or -1 for default pointer size based upon datatype manager
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 */
	public PointerTypedef(String typeDefName, DataType referencedDataType, int pointerSize,
			DataTypeManager dtm) {
		super(getCategoryPath(referencedDataType), getTempNameIfNeeded(typeDefName), dtm);
		isAutoNamed = StringUtils.isBlank(typeDefName);
		modelTypedef =
			new TypedefDataType("TEMP", new PointerDataType(referencedDataType, pointerSize, dtm));
	}

	/**
	 * Constructs a pointer-typedef without any settings
	 * @param typeDefName name of this pointer-typedef or null to use auto-named typedef.
	 * @param pointerDataType associated pointer datatype
	 * @param dtm data-type manager whose data organization should be used (highly recommended, may be null)
	 */
	public PointerTypedef(String typeDefName, Pointer pointerDataType, DataTypeManager dtm) {
		super(pointerDataType.getCategoryPath(), getTempNameIfNeeded(typeDefName), dtm);
		isAutoNamed = StringUtils.isBlank(typeDefName);
		modelTypedef = new TypedefDataType("TEMP", pointerDataType.clone(dtm));
	}

	private static CategoryPath getCategoryPath(DataType referencedDataType) {
		return referencedDataType != null ? referencedDataType.getCategoryPath()
				: CategoryPath.ROOT;
	}

	private static String getTempNameIfNeeded(String baseName) {
		return StringUtils.isBlank(baseName) ? "TEMP" : baseName;
	}

	private static int getPreferredPointerSize(int pointerSize, DataTypeManager dtm,
			AddressSpace space) {
		Objects.requireNonNull(space, "Address space must be specified");
		if (pointerSize > 0) {
			return pointerSize;
		}
		pointerSize = space.getSize() / 8;
		if (dtm.getDataOrganization().getPointerSize() == pointerSize) {
			pointerSize = -1;
		}
		return pointerSize;
	}

	@Override
	public void enableAutoNaming() {
		isAutoNamed = true;
	}

	@Override
	public boolean isAutoNamed() {
		return isAutoNamed;
	}

	/**
	 * Get the referenced datatype used to construct this datatype
	 * (datatype which pointer references).
	 * @return referenced datatype
	 */
	protected DataType getReferencedDataType() {
		Pointer ptrType = (Pointer) getDataType();
		return ptrType.getDataType();
	}

	public UniversalID getUniversalID() {
		return universalId;
	}

	@Override
	public boolean isEquivalent(DataType obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || !(obj instanceof TypeDef)) {
			return false;
		}
		TypeDef td = (TypeDef) obj;
		if (!DataTypeUtilities.equalsIgnoreConflict(getName(), td.getName())) {
			return false;
		}
		if (!hasSameTypeDefSettings(td)) {
			return false;
		}
		return DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), td.getDataType());
	}

	@Override
	public String getDescription() {
		return "Pointer-Typedef";
	}

	@Override
	public String getName() {
		if (isAutoNamed) {
			// Do not cache name since we do not have listeners to detect 
			// settings change which may impact name generation.
			return TypedefDataType.generateTypedefName(this);
		}
		return super.getName(); // use name provided at instantiation
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return modelTypedef.hasLanguageDependantLength();
	}

	@Override
	public int getLength() {
		return modelTypedef.getLength();
	}

	@Override
	public int getAlignedLength() {
		return modelTypedef.getAlignedLength();
	}

	@Override
	public DataType getDataType() {
		return modelTypedef.getDataType();
	}

	@Override
	public DataType getBaseDataType() {
		return modelTypedef.getBaseDataType();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return modelTypedef.getSettingsDefinitions();
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return modelTypedef.getTypeDefSettingsDefinitions();
	}

	@Override
	public Settings getDefaultSettings() {
		return modelTypedef.getDefaultSettings();
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	public String toString() {
		if (isAutoNamed) {
			return getClass().getSimpleName() + ": " + getName();
		}
		return getClass().getSimpleName() + ": typedef " + getName() + " " +
			getDataType().getName();
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return modelTypedef.getValueClass(settings);
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return modelTypedef.getValue(buf, settings, length);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return modelTypedef.getRepresentation(buf, settings, length);
	}

	@Override
	public PointerTypedef clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		return copy(dtm);
	}

	@Override
	public PointerTypedef copy(DataTypeManager dtm) {
		Pointer ptrType = (Pointer) getDataType();
		String n = isAutoNamed ? null : getName();
		PointerTypedef td = new PointerTypedef(n, ptrType, getDataTypeManager());
		TypedefDataType.copyTypeDefSettings(this, td, false);
		return td;
	}
}
