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

import java.util.*;

import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Empty stub of {@link DataTypeManager}
 */
public class TestDummyDataTypeManager implements DataTypeManager {

	@Override
	public UniversalID getUniversalID() {
		// stub
		return null;
	}

	@Override
	public boolean containsCategory(CategoryPath path) {
		// stub
		return false;
	}

	@Override
	public String getUniqueName(CategoryPath path, String baseName) {
		// stub
		return null;
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		// stub
		return null;
	}

	@Override
	public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
		// stub
		return null;
	}

	@Override
	public void addDataTypes(Collection<DataType> dataTypes, DataTypeConflictHandler handler,
			TaskMonitor monitor) throws CancelledException {
		// stub
	}

	@Override
	public Iterator<DataType> getAllDataTypes() {
		// stub
		return null;
	}

	@Override
	public void getAllDataTypes(List<DataType> list) {
		// stub

	}

	@Override
	public Iterator<Structure> getAllStructures() {
		// stub
		return null;
	}

	@Override
	public Iterator<Composite> getAllComposites() {
		// stub
		return null;
	}

	@Override
	public void findDataTypes(String name, List<DataType> list) {
		// stub

	}

	@Override
	public void findDataTypes(String name, List<DataType> list, boolean caseSensitive,
			TaskMonitor monitor) {
		// stub

	}

	@Override
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		// stub
		return null;
	}

	@Override
	public DataType getDataType(String dataTypePath) {
		// stub
		return null;
	}

	@Override
	public DataType findDataType(String dataTypePath) {
		// stub
		return null;
	}

	@Override
	public DataType getDataType(DataTypePath dataTypePath) {
		// stub
		return null;
	}

	@Override
	public long getResolvedID(DataType dt) {
		// stub
		return 0;
	}

	@Override
	public long getID(DataType dt) {
		// stub
		return 0;
	}

	@Override
	public DataType getDataType(long dataTypeID) {
		// stub
		return null;
	}

	@Override
	public Category getCategory(long categoryID) {
		// stub
		return null;
	}

	@Override
	public Category getCategory(CategoryPath path) {
		// stub
		return null;
	}

	@Override
	public void dataTypeChanged(DataType dataType, boolean isAutoChange) {
		// stub

	}

	@Override
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l) {
		// stub

	}

	@Override
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l) {
		// stub

	}

	@Override
	public void addInvalidatedListener(InvalidatedListener listener) {
		// stub

	}

	@Override
	public void removeInvalidatedListener(InvalidatedListener listener) {
		// stub

	}

	@Override
	public boolean remove(DataType dataType, TaskMonitor monitor) {
		// stub
		return false;
	}

	@Override
	public boolean contains(DataType dataType) {
		// stub
		return false;
	}

	@Override
	public Category createCategory(CategoryPath path) {
		// stub
		return null;
	}

	@Override
	public DataType getDataType(CategoryPath path, String name) {
		// stub
		return null;
	}

	@Override
	public String getName() {
		// stub
		return null;
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		// stub

	}

	@Override
	public int startTransaction(String description) {
		// stub
		return 0;
	}

	@Override
	public boolean isUpdatable() {
		// stub
		return false;
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		// stub

	}

	@Override
	public void flushEvents() {
		// stub

	}

	@Override
	public void close() {
		// stub

	}

	@Override
	public Pointer getPointer(DataType datatype) {
		// stub
		return null;
	}

	@Override
	public Pointer getPointer(DataType datatype, int size) {
		// stub
		return null;
	}

	@Override
	public Category getRootCategory() {
		// stub
		return null;
	}

	@Override
	public boolean isFavorite(DataType datatype) {
		// stub
		return false;
	}

	@Override
	public void setFavorite(DataType datatype, boolean isFavorite) {
		// stub

	}

	@Override
	public List<DataType> getFavorites() {
		// stub
		return null;
	}

	@Override
	public int getCategoryCount() {
		// stub
		return 0;
	}

	@Override
	public int getDataTypeCount(boolean includePointersAndArrays) {
		// stub
		return 0;
	}

	@Override
	public void findEnumValueNames(long value, Set<String> enumValueNames) {
		// stub

	}

	@Override
	public DataType getDataType(SourceArchive sourceArchive, UniversalID datatypeID) {
		// stub
		return null;
	}

	@Override
	public DataType findDataTypeForID(UniversalID datatypeID) {
		// stub
		return null;
	}

	@Override
	public long getLastChangeTimeForMyManager() {
		// stub
		return 0;
	}

	@Override
	public SourceArchive getSourceArchive(UniversalID sourceID) {
		// stub
		return null;
	}

	@Override
	public ArchiveType getType() {
		// stub
		return null;
	}

	@Override
	public List<DataType> getDataTypes(SourceArchive sourceArchive) {
		// stub
		return null;
	}

	@Override
	public SourceArchive getLocalSourceArchive() {
		// stub
		return null;
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		// stub

	}

	@Override
	public void disassociate(DataType datatype) {
		// stub

	}

	@Override
	public boolean updateSourceArchiveName(String archiveFileID, String name) {
		// stub
		return false;
	}

	@Override
	public boolean updateSourceArchiveName(UniversalID sourceID, String name) {
		// stub
		return false;
	}

	@Override
	public DataOrganization getDataOrganization() {
		// stub
		return null;
	}

	@Override
	public List<SourceArchive> getSourceArchives() {
		// stub
		return null;
	}

	@Override
	public void removeSourceArchive(SourceArchive sourceArchive) {
		// stub

	}

	@Override
	public SourceArchive resolveSourceArchive(SourceArchive sourceArchive) {
		// stub
		return null;
	}

	@Override
	public Set<DataType> getDataTypesContaining(DataType dataType) {
		// stub
		return null;
	}

}
