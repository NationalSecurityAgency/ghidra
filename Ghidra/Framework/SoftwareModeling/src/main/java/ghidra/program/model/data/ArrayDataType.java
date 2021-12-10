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

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Basic implementation of the Array interface.
 */
public class ArrayDataType extends DataTypeImpl implements Array {

	private int numElements;
	private DataType dataType;
	private int elementLength;
	private boolean deleted = false;

	/**
	 * Constructs a new Array dataType.
	 * @param dataType the dataType of the elements in the array (null is not permitted).
	 * @param numElements the number of elements in the array (0 is permitted).
	 * @param elementLength the length of an individual element in the array.  This value
	 * is only used for {@link Dynamic} dataType where {@link Dynamic#canSpecifyLength()} 
	 * returns true.
	 */
	public ArrayDataType(DataType dataType, int numElements, int elementLength) {
		this(dataType, numElements, elementLength, null);
	}

	/**
	 * Constructs a new Array dataType.
	 * @param dataType the dataType of the elements in the array.
	 * @param numElements the number of elements in the array (0 is permitted).
	 * @param elementLength the length of an individual element in the array.  This value
	 * is only used for {@link Dynamic} dataType where {@link Dynamic#canSpecifyLength()} 
	 * returns true.
	 * @param dtm datatype manager or null
	 */
	public ArrayDataType(DataType dataType, int numElements, int elementLength,
			DataTypeManager dtm) {
		super(dataType.getCategoryPath(), "array", dtm);
		if (numElements < 0) {
			throw new IllegalArgumentException(
				"Number of array elements may not be negative [" + numElements + "]");
		}
		DataType baseDt = dataType;
		if (dataType instanceof TypeDef) {
			baseDt = ((TypeDef) dataType).getBaseDataType();
		}
		validate(baseDt);
		dataType = dataType.clone(dtm);
		this.elementLength = -1;
		if (baseDt instanceof Dynamic) {
			if (elementLength < 0) {
				throw new IllegalArgumentException(
					"Must specify Array element-length for dynamic " +
						dataType.getClass().getSimpleName());
			}
			this.elementLength = elementLength;
		}
		this.dataType = dataType;
		this.numElements = numElements;
		name = DataTypeUtilities.getName(this, true);
		dataType.addParent(this);
	}

	/**
	 * Validate a array base datatype to ensure that it is allowed
	 * @param baseDt intended base datatype for array (always pass in typedef's base type if applicable)
	 * @throws IllegalArgumentException if dt is not a valid base datatype for an array
	 */
	private static void validate(DataType baseDt) throws IllegalArgumentException {
		if (baseDt instanceof BitFieldDataType) {
			throw new IllegalArgumentException(
				"Array data-type may not be a bitfield: " + baseDt.getName());
		}
		if (baseDt instanceof FactoryDataType) {
			throw new IllegalArgumentException(
				"Array data-type may not be a Factory data-type: " + baseDt.getName());
		}
		if (baseDt instanceof Dynamic) {
			if (!((Dynamic) baseDt).canSpecifyLength()) {
				throw new IllegalArgumentException(
					"Array data-type may not be a non-sizable Dynamic data-type: " + baseDt.getName());
			}
		}
		else if (baseDt.getLength() < 1) { // not Dynamic
			throw new IllegalArgumentException(
				"Data type may not report a length less than 1: " + baseDt.getClass().getSimpleName());
		}
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return dataType.hasLanguageDependantLength();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		// NOTE: it may be necessary to allow array-specific settings at some
		// point to facilitate appropriate char array string generation
		return getDataType().getSettingsDefinitions();
	}

	@Override
	public boolean isEquivalent(DataType obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof Array)) {
			return false;
		}
		Array array = (Array) obj;
		if (numElements != array.getNumElements()) {
			return false;
		}
		if (!dataType.isEquivalent(array.getDataType())) {
			return false;
		}
		if (dataType instanceof Dynamic && getElementLength() != array.getElementLength()) {
			return false;
		}
		return true;
	}

	@Override
	public int getNumElements() {
		return numElements;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return DataTypeUtilities.getMnemonic(this, false, settings);
	}

	@Override
	public boolean isZeroLength() {
		return numElements == 0;
	}

	@Override
	public int getLength() {
		if (numElements == 0) {
			return 1; // 0-length datatype instance not supported
		}
		return numElements * getElementLength();
	}

	@Override
	public String getDescription() {
		return "Array of " + dataType.getDisplayName();
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public final DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new ArrayDataType(dataType.clone(dtm), numElements, getElementLength(), dtm);
	}

	@Override
	public final DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (dt == dataType) {
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (dt == dataType) {
			notifyAlignmentChanged();
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return getArrayValueClass(settings);
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		// unsupported - ignore
	}

	@Override
	public int getElementLength() {
		return (dataType instanceof Dynamic) ? elementLength : dataType.getLength();
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (dataType == dt) {
			notifyDeleted();
			deleted = true;
		}
	}

	@Override
	public boolean isDeleted() {
		return deleted;
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (newDt == this || newDt.getLength() < 0) {
			newDt = DataType.DEFAULT;
		}
		if (dataType == oldDt) {
			String oldName = getName();
			int oldLength = getLength();
			int oldAlignment = getAlignment();
			int oldElementLength = getElementLength();
			dataType.removeParent(this);
			dataType = newDt;
			dataType.addParent(this);
			elementLength = newDt.getLength() < 0 ? oldElementLength : -1;
			if (!getName().equals(oldName)) {
				notifyNameChanged(oldName);
			}
			if (getLength() != oldLength || oldElementLength != getElementLength()) {
				notifySizeChanged();
			}
			else if (getAlignment() != oldAlignment) {
				notifyAlignmentChanged();
			}
		}
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// unsupported - ignore
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		// unsupported - ignore
	}

	@Override
	public CategoryPath getCategoryPath() {
		DataType dt = getDataType();
		return dt.getCategoryPath();
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		if (dataType == dt) {
			notifyNameChanged(oldName);
		}
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	public String getDefaultLabelPrefix() {
		DataType dt = getDataType();
		if (dt == DataType.DEFAULT) {
			return ARRAY_LABEL_PREFIX;
		}
		return dt.getDefaultLabelPrefix() + "_" + ARRAY_LABEL_PREFIX;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getArrayDefaultLabelPrefix(buf, settings, len, options);
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		return getArrayDefaultOffcutLabelPrefix(buf, settings, len, options, offcutLength);
	}

	@Override
	public long getLastChangeTime() {
		return 0;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getArrayValue(buf, settings, length);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getArrayRepresentation(buf, settings, length);
	}

}
