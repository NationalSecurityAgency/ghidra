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
package ghidra.program.database.data;

import java.io.IOException;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.dtarchive.DataTypeArchiveDB;
import ghidra.program.database.symbol.VariableStorageManager;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.util.Lock;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Data type manager for built in types that do not live anywhere except
 * in memory.
 */
public final class BuiltInDataTypeManagerDB extends ArchiveDataTypeManagerDB
		implements BuiltInDataTypeManager {

	public BuiltInDataTypeManagerDB(DBHandle handle,
			OpenMode openMode, ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		super(handle, openMode, errHandler, lock, monitor);
	}

	@Override
	public void setDomainObject(DataTypeArchiveDB archive) {
		this.archive = archive;
	}

	@Override
	protected final void setProgramArchitecture(ProgramArchitecture programArchitecture,
			VariableStorageManager variableStorageMgr, boolean force, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException("program architecture change not permitted");
	}

	@Override
	protected final boolean isArchitectureChangeAllowed() {
		return false;
	}

	@Override
	public Category createCategory(CategoryPath path) {
		if (path != CategoryPath.ROOT) {
			throw new UnsupportedOperationException(
				"Built-in category limited to root category only");
		}
		return super.createCategory(path);
	}

	protected UniversalID resolveSourceArchiveID(DataType dataType) {
		if (dataType instanceof BuiltInDataType) {
			return DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
		}
		throw new IllegalArgumentException("Only Built-in data types can be resolved by the " +
			getClass().getSimpleName() + " manager.");
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.BUILT_IN;
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		return super.resolve(dataType, BUILT_IN_MANAGER_HANDLER);
	}

	@Override
	public DataType addDataType(DataType originalDataType, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized void close() {
		// cannot close a built-in data type manager; close performed automatically during shutdown
	}

	private final static DataTypeConflictHandler BUILT_IN_MANAGER_HANDLER =
		new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			throw new UnsupportedOperationException(
				"Built-in data-types may not be substantially changed while Ghidra is running");
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return false;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return this;
		}
	};
}
