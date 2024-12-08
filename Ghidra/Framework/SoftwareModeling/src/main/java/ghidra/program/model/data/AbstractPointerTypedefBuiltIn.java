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

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;

/**
 * <code>AbstractPointerTypedefDataType</code> provides an abstract {@link BuiltIn} datatype 
 * implementation for a pointer-typedef datatype.
 */
public abstract class AbstractPointerTypedefBuiltIn extends BuiltIn implements TypeDef {

	private String typedefName;
	private TypedefDataType modelTypedef;
	private UniversalID universalId = UniversalIdGenerator.nextID();

	/**
	 * Constructs a pointer-typedef.  The category path will match that of the 
	 * referencedDataType. Subclass may set various default settings which correspond to 
	 * {@link PointerTypeSettingsDefinition}.
	 * @param name name of this pointer-typedef or null to force auto-name generation.
	 * @param referencedDataType data type this pointer points to
	 * @param pointerSize pointer size in bytes or -1 for default pointer size
	 * @param dtm data-type manager whose data organization should be used
	 */
	protected AbstractPointerTypedefBuiltIn(String name, DataType referencedDataType,
			int pointerSize, DataTypeManager dtm) {
		super(getCategoryPath(referencedDataType), getTempNameIfNeeded(name), dtm);
		setTypedefName(name);
		modelTypedef =
			new TypedefDataType("TEMP", new PointerDataType(referencedDataType, pointerSize, dtm));
		setDefaultSettings(modelTypedef.getDefaultSettings());
	}

	/**
	 * Constructs a pointer-typedef.  The category path will match that of the 
	 * pointerDataType. Subclass may set various default settings which correspond to 
	 * {@link PointerTypeSettingsDefinition}.
	 * @param name name of this pointer-typedef or null to force auto-name generation.
	 * @param pointerDataType associated pointer datatype (required)
	 * @param dtm data-type manager whose data organization should be used
	 */
	protected AbstractPointerTypedefBuiltIn(String name, Pointer pointerDataType,
			DataTypeManager dtm) {
		super(pointerDataType.getCategoryPath(), getTempNameIfNeeded(name), dtm);
		setTypedefName(name);
		modelTypedef = new TypedefDataType("TEMP", pointerDataType.clone(dtm));
		setDefaultSettings(modelTypedef.getDefaultSettings());
	}

	@Override
	public void enableAutoNaming() {
		typedefName = null;
	}

	@Override
	public boolean isAutoNamed() {
		return typedefName == null;
	}

	private static CategoryPath getCategoryPath(DataType referencedDataType) {
		return referencedDataType != null ? referencedDataType.getCategoryPath()
				: CategoryPath.ROOT;
	}

	private static String getTempNameIfNeeded(String baseName) {
		return StringUtils.isBlank(baseName) ? "TEMP" : baseName;
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

	protected boolean hasGeneratedNamed() {
		return (typedefName == null);
	}

	void setTypedefName(String name) {
		if (name != null && !DataUtilities.isValidDataTypeName(name)) {
			throw new IllegalArgumentException("Invalid DataType name: " + name);
		}
		this.typedefName = name;
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
	public String getName() {
		if (typedefName == null) {
			// Do not cache name since we do not have listeners to detect 
			// settings change which may impact name generation.
			return TypedefDataType.generateTypedefName(this);
		}
		return typedefName; // use name provided at instantiation
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
	public SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return modelTypedef.getSettingsDefinitions();
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": typedef " + getName() + " " +
			getDataType().getName();
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		if (settings == null) {
			settings = getDefaultSettings();
		}
		return modelTypedef.getValueClass(settings);
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		if (settings == null) {
			settings = getDefaultSettings();
		}
		return modelTypedef.getValue(buf, settings, length);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (settings == null) {
			settings = getDefaultSettings();
		}
		return modelTypedef.getRepresentation(buf, settings, length);
	}

}
