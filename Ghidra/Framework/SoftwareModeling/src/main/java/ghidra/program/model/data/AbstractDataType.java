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

import java.net.URL;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * Base class for DataType classes. Many of the DataType methods are stubbed out so simple datatype
 * classes can be created without implementing too many methods.
 */
public abstract class AbstractDataType implements DataType {
	protected String name;
	protected CategoryPath categoryPath;
	protected final DataTypeManager dataMgr;
	private DataOrganization dataOrganization;

	protected AbstractDataType(CategoryPath path, String name, DataTypeManager dataTypeManager) {
		if (path == null) {
			throw new IllegalArgumentException("Category Path is null!");
		}
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Name is null or empty!");
		}
		// allow spaces since derived types may have spaces (pointers for example: foo *32)
		if (!DataUtilities.isValidDataTypeName(name)) {
			throw new IllegalArgumentException("Invalid DataType name: " + name);
		}

		this.categoryPath = path;
		this.name = name;
		this.dataMgr = dataTypeManager;
	}

	@Override
	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDataTypeManager()
	 */
	@Override
	public final DataTypeManager getDataTypeManager() {
		return dataMgr;
	}

	@Override
	public final DataOrganization getDataOrganization() {
		if (dataOrganization != null) {
			return dataOrganization;
		}
		if (dataMgr != null) {
			dataOrganization = dataMgr.getDataOrganization();
		}
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}
		return dataOrganization;
	}

	@Override
	public DataTypePath getDataTypePath() {
		return new DataTypePath(categoryPath, name);
	}

	@Override
	public URL getDocs() {
		return null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getPathName() {
		return getDataTypePath().getPath();
	}

	@Override
	public String getDisplayName() {
		return getName();
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public boolean isNotYetDefined() {
		return false;
	}

	@Override
	public boolean isZeroLength() {
		return false;
	}

	@Override
	public String toString() {
		return getDisplayName();
	}

	@Override
	public boolean isDeleted() {
		return false;
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		// default is immutable
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		// default is immutable
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// do nothing
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		// do nothing
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		// do nothing
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		// do nothing
	}

	@Override
	public void addParent(DataType dt) {
		// not-applicable
	}

	@Override
	public void removeParent(DataType dt) {
		// not-applicable
	}

	@Override
	public DataType[] getParents() {
		// not-applicable
		return null;
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public SourceArchive getSourceArchive() {
		return null; 		// do nothing
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		// do nothing
	}

	@Override
	public long getLastChangeTime() {
		// do nothing
		return 0;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		// do nothing
		return 0;
	}

	@Override
	public UniversalID getUniversalID() {
		return null;
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// do nothing
	}

	@Override
	public void replaceWith(DataType dataType) {
		// do nothing
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		// do nothing
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		// do nothing
	}

	@Override
	public void setDescription(String description) throws UnsupportedOperationException {
		// immutable
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return false; // not applicable
	}

	@Override
	public String getDefaultLabelPrefix() {
		return null;
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		return getDefaultLabelPrefix();
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// not-applicable
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getDefaultLabelPrefix();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		// By default we will do nothing different for offcut values
		return getDefaultLabelPrefix(buf, settings, len, options);
	}
}
