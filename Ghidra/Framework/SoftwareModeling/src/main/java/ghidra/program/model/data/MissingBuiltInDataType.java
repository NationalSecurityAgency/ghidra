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

import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.DuplicateNameException;

/**
 * Provides an implementation of a data type that stands-in for a missing Built-In data type.
 *  <P> 
 *  This field is not meant to be loaded by the {@link ClassSearcher}, hence the X in the name.
 */
public class MissingBuiltInDataType extends DataTypeImpl implements Dynamic {

	private final static long serialVersionUID = 1;

	private String missingBuiltInClassPath;
	private String missingBuiltInName;

	/**
	 * Construct a Missing Data Type
	 * @param path category path
	 * @param missingBuiltInName name of missing built-in datatype for which this will standin for.
	 * @param missingBuiltInClassPath classpath of missing built-in datatype for which this will standin for.
	 */
	public MissingBuiltInDataType(CategoryPath path, String missingBuiltInName,
			String missingBuiltInClassPath, DataTypeManager dtm) {
		super(path == null ? CategoryPath.ROOT : path, "-MISSING-" + missingBuiltInName, null,
			BuiltInSourceArchive.INSTANCE, NO_SOURCE_SYNC_TIME, NO_LAST_CHANGE_TIME, dtm);
		this.missingBuiltInName = missingBuiltInName;
		this.missingBuiltInClassPath = missingBuiltInClassPath;
	}

	/**
	 * set the category for this data type
	 */
	protected void setCategory() {
		return;
	}

	/**
	 * Returns name of missing built-in datatype for which this type is standing-in for
	 */
	public String getMissingBuiltInName() {
		return missingBuiltInName;
	}

	/**
	 * Returns classpath of missing built-in datatype for which this type is standing-in for
	 */
	public String getMissingBuiltInClassPath() {
		return missingBuiltInClassPath;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.program.model.data.Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return getName();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	/**
	 * @see ghidra.program.model.data.Dynamic#getLength(ghidra.program.model.mem.MemBuffer, int)
	 */
	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		return -1;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Missing Built-In Data Type: " + missingBuiltInClassPath;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return missingBuiltInClassPath;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext, ghidra.program.model.data.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return missingBuiltInClassPath;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MissingBuiltInDataType(categoryPath, missingBuiltInName, missingBuiltInClassPath,
			dtm);
	}

	/**
	 * @see ghidra.program.model.data.DataType#copy(ghidra.program.model.data.DataTypeManager)
	 */
	@Override
	public final DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == null) {
			return false;
		}
		if (dt == this) {
			return true;
		}
		if (!(dt instanceof MissingBuiltInDataType)) {
			return false;
		}
		return missingBuiltInClassPath.equals(
			((MissingBuiltInDataType) dt).missingBuiltInClassPath);
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
	}

	@Override
	public void setName(String name) throws InvalidNameException {
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
	}

	@Override
	public long getLastChangeTime() {
		return NO_SOURCE_SYNC_TIME;
	}

	/**
	 * @see ghidra.program.model.data.BuiltInDataType#getCTypeDeclaration(ghidra.program.model.data.DataOrganization)
	 */
	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return null; // missing type
	}

	@Override
	public DataType getReplacementBaseType() {
		return null;
	}
}
