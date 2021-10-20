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

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.ChangeListener;

import ghidra.framework.ShutdownHookRegistry;
import ghidra.framework.ShutdownPriority;
import ghidra.util.*;
import ghidra.util.classfinder.ClassFilter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * Data type manager for built in types that do not live anywhere except
 * in memory.
 */
public class BuiltInDataTypeManager extends StandAloneDataTypeManager {

	// TODO: There appear to be many public methods in DataTypeManagerDB which could potentially modify the 
	// underlying database - these methods should probably be overridden

	private static BuiltInDataTypeManager manager;
	private ChangeListener classSearcherListener = e -> refresh();

	/**
	 * Returns shared instance of built-in data type manager.
	 * @return the manager
	 */
	public static synchronized BuiltInDataTypeManager getDataTypeManager() {
		if (manager == null) {
			manager = new BuiltInDataTypeManager();
			Runnable cleanupTask = () -> {
				if (manager != null) {
					manager.closeStaticInstance();
					manager = null;
				}
			};
			ShutdownHookRegistry.addShutdownHook(cleanupTask,
				ShutdownPriority.DISPOSE_DATABASES.before());
		}
		return manager;
	}

	private BuiltInDataTypeManager() {
		super(BUILT_IN_DATA_TYPES_NAME);
		initialize();
	}

	@Override
	public synchronized int startTransaction(String description) {
		if (manager != null) {
			throw new UnsupportedOperationException(
				"Built-in datatype manager may not be modified");
		}
		return super.startTransaction(description);
	}

	@Override
	public synchronized void endTransaction(int transactionID, boolean commit) {
		if (manager != null) {
			throw new UnsupportedOperationException();
		}
		super.endTransaction(transactionID, commit);
	}

	@Override
	public Category createCategory(CategoryPath path) {
		if (path != CategoryPath.ROOT) {
			throw new UnsupportedOperationException(
				"Built-in category limited to root category only");
		}
		return super.createCategory(path);
	}

	private synchronized void closeStaticInstance() {
		ClassSearcher.removeChangeListener(classSearcherListener);
		super.close();
	}

	/**
	 * Refresh the list of Built-In data types found by searching the class path.
	 */
	private synchronized void refresh() {
		populateBuiltInTypes();
	}

	private void initialize() {
		try {
			populateBuiltInTypes();
		}
		catch (Throwable t) {
			Msg.showError(this, null, "Error", "Error populating Built In Data Types", t);
		}
		ClassSearcher.addChangeListener(classSearcherListener);
	}

	/**
	 * Add the built in data types to the default built in folder if they
	 * were not found in any other category.
	 */
	protected void populateBuiltInTypes() {
		int id = super.startTransaction("Populate");
		try {

			List<DataType> list = new ArrayList<>();
			ClassFilter filter = new BuiltInDataTypeClassExclusionFilter();
			List<BuiltInDataType> datatypes =
				ClassSearcher.getInstances(BuiltInDataType.class, filter);
			for (BuiltInDataType datatype : datatypes) {
				list.clear();
				findDataTypes(datatype.getName(), list);
				if (list.size() == 0) {
					super.resolve(datatype, null);
				}
				else if (!list.get(0).isEquivalent(datatype)) {
					Msg.showError(this, null, "Invalid BuiltIn Data Type",
						"BuiltIn datatype name collision between " +
							datatype.getClass().getSimpleName() + " and " +
							list.get(0).getClass().getSimpleName() + ", both named '" +
							datatype.getName() + "'");
				}
				else if (list.size() != 1) {
					throw new AssertException("Should be no duplicate named built-in types");
				}
			}
		}
		finally {
			super.endTransaction(id, true);
		}

	}

	protected UniversalID resolveSourceArchiveID(DataType dataType) {
		if (dataType instanceof BuiltInDataType) {
			return DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID;
		}
		throw new IllegalArgumentException(
			"Only Built-in data types can be resolved by the " + getClass().getSimpleName() +
				" manager.");
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.BUILT_IN;
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		return super.resolve(dataType, DataTypeConflictHandler.BUILT_IN_MANAGER_HANDLER);
	}

	@Override
	public DataType addDataType(DataType originalDataType, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(DataType dataType, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void close() {
		// cannot close a built-in data type manager; close performed automatically during shutdown
	}
}
