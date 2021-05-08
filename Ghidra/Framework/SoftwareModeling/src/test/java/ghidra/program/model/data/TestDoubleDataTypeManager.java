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

import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A stub of the {@link DataTypeManager} interface.  This can be used to supply a test values 
 * or to spy on system internals by overriding methods as needed.
 */
public class TestDoubleDataTypeManager implements DataTypeManager {

	private UniversalID id;

	public TestDoubleDataTypeManager() {
		this.id = UniversalIdGenerator.nextID();
	}

	@Override
	public UniversalID getUniversalID() {
		return id;
	}

	@Override
	public boolean containsCategory(CategoryPath path) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getUniqueName(CategoryPath path, String baseName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addDataTypes(Collection<DataType> dataTypes, DataTypeConflictHandler handler,
			TaskMonitor monitor) throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<DataType> getAllDataTypes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void getAllDataTypes(List<DataType> list) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Structure> getAllStructures() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Composite> getAllComposites() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void findDataTypes(String name, List<DataType> list) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void findDataTypes(String name, List<DataType> list, boolean caseSensitive,
			TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(String dataTypePath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType findDataType(String dataTypePath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(DataTypePath dataTypePath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getResolvedID(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getID(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(long dataTypeID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getCategory(long categoryID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getCategory(CategoryPath path) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeChanged(DataType dataType, boolean isAutoChange) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addInvalidatedListener(InvalidatedListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeInvalidatedListener(InvalidatedListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(DataType dataType, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category createCategory(CategoryPath path) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(CategoryPath path, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int startTransaction(String description) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUpdatable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void flushEvents() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void close() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Pointer getPointer(DataType datatype) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Pointer getPointer(DataType datatype, int size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getRootCategory() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isFavorite(DataType datatype) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setFavorite(DataType datatype, boolean isFavorite) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getFavorites() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getCategoryCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getDataTypeCount(boolean includePointersAndArrays) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void findEnumValueNames(long value, Set<String> enumValueNames) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(SourceArchive sourceArchive, UniversalID datatypeID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType findDataTypeForID(UniversalID datatypeID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastChangeTimeForMyManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceArchive getSourceArchive(UniversalID sourceID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ArchiveType getType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getDataTypes(SourceArchive sourceArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceArchive getLocalSourceArchive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void disassociate(DataType datatype) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean updateSourceArchiveName(String archiveFileID, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean updateSourceArchiveName(UniversalID sourceID, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataOrganization getDataOrganization() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<SourceArchive> getSourceArchives() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeSourceArchive(SourceArchive sourceArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceArchive resolveSourceArchive(SourceArchive sourceArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<DataType> getDataTypesContaining(DataType dataType) {
		throw new UnsupportedOperationException();
	}
}
