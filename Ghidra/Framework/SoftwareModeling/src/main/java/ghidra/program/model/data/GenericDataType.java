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

import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * Base implementation for a generic data type.
 */
public abstract class GenericDataType extends DataTypeImpl {

	protected GenericDataType(CategoryPath path, String name, DataTypeManager dataMgr) {
		super(path, name, dataMgr);
		if (!DataUtilities.isValidDataTypeName(name)) {
			throw new IllegalArgumentException("Invalid DataType name: " + name);
		}
	}

	protected GenericDataType(CategoryPath path, String name, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dataMgr) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dataMgr);
		if (!DataUtilities.isValidDataTypeName(name)) {
			throw new IllegalArgumentException("Invalid DataType name: " + name);
		}
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {

		doSetName(name);
		doSetCategoryPath(path);
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		doSetName(name);
	}

	private void doSetName(String newName) throws InvalidNameException {
		if (this.name.equals(newName)) {
			return;
		}
		checkValidName(newName);
		String oldName = this.name;
		this.name = newName;
		notifyNameChanged(oldName);
	}

	@Override
	public void setCategoryPath(CategoryPath path) {
		doSetCategoryPath(path);
	}

	private void doSetCategoryPath(CategoryPath path) {
		if (path == null) {
			path = CategoryPath.ROOT;
		}
		categoryPath = path;
	}

}
