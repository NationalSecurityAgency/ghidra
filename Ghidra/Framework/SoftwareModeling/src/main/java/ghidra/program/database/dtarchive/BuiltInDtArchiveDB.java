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
package ghidra.program.database.dtarchive;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.DBHandle;
import ghidra.framework.ShutdownHookRegistry;
import ghidra.framework.ShutdownPriority;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.RuntimeIOException;
import ghidra.program.database.data.BuiltInDataTypeManagerDB;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassFilter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * DataTypeArchive containing all found built-in datatypes.
 */
public class BuiltInDtArchiveDB extends DataTypeArchiveDB {
	private static volatile BuiltInDtArchiveDB INSTANCE;

	private BuiltInDtArchiveDB() throws IOException {
		super(new DBHandle(), DataTypeManager.BUILT_IN_DATA_TYPES_NAME, new Object());
		initialize();
		setImmutable();
	}

	@Override
	protected BuiltInDataTypeManagerDB createDataTypeManager(DBHandle handle, OpenMode openMode,
			TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return new BuiltInDataTypeManagerDB(handle, openMode, this, lock, monitor);
	}

	private void initialize() {
		try {
			populateBuiltInTypes();
		}
		catch (Throwable t) {
			Msg.showError(this, null, "Error", "Error populating Built In Data Types", t);
		}
	}

	@Override
	public boolean isTemporary() {
		return true;
	}

	@Override
	public boolean isUpdatable() {
		return false;
	}

	@Override
	public String getDescription() {
		return "Buit-in Data Type Archive";
	}

	@Override
	protected boolean isArchitectureChangeAllowed() {
		return false;
	}

	/**
	 * Add the built in data types to the default built in folder if they
	 * were not found in any other category.
	 */
	protected void populateBuiltInTypes() {
		withTransaction("Populate Built-in Datatypes", () -> {
			ClassFilter filter = new BuiltInDataTypeClassExclusionFilter();
			List<BuiltInDataType> datatypes =
				ClassSearcher.getInstances(BuiltInDataType.class, filter);
			if (!resolveBuiltInDataTypes(datatypes)) {
				Msg.showError(this, null, "Built-in Datatype Name Collision",
					"One or more Built-in datatypes were discovered with the same name. \n" + "" +
						"See the console or log for the list of duplicate datatype names");
			}
		});
	}

	private boolean resolveBuiltInDataTypes(List<BuiltInDataType> datatypes) {
		BuiltInDataTypeManager dtm = getDataTypeManager();
		List<DataType> list = new ArrayList<>();
		boolean hadNameCollisions = false;

		for (BuiltInDataType datatype : datatypes) {
			list.clear();
			dtm.findDataTypes(datatype.getName(), list);
			if (list.size() > 1) {
				// This can't happen since we don't add in built-ins that collide, so at most
				// there can only ever be one in the list.
				throw new AssertException(
					"Found multiple resolved built-in datatypes with the same name!");
			}
			if (!list.isEmpty()) {
				DataType resolvedDt = list.get(0);
				if (!resolvedDt.isEquivalent(resolvedDt)) {
					Msg.error(this,
						"Found duplicate built-in datatype with name " + datatype.getName());
					hadNameCollisions = true;
				}
				// At this point we have a dupe, either way we don't resolve it. It is either
				// the same datatype but already resolved(dtm assigned) or is is an incompatible
				// duplicate that we just reported.
				continue;
			}
			dtm.resolve(datatype, null);
		}
		return !hadNameCollisions;
	}

	private void closeStaticInstance() {
		close();
	}

	@Override
	protected void finalize() throws Throwable {
		close();
	}

	@Override
	public BuiltInDataTypeManagerDB getDataTypeManager() {
		return (BuiltInDataTypeManagerDB) super.getDataTypeManager();
	}

	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.BUILT_IN;
	}

	/**
	 * Returns shared instance of built-in data type archive.
	 * @return the built-in data type archive
	 */
	public static synchronized BuiltInDtArchiveDB getDataTypeArchive() {
		if (INSTANCE == null) {
			try {
				INSTANCE = new BuiltInDtArchiveDB();
			}
			catch (IOException e) {
				throw new RuntimeIOException(e);
			}
			Runnable cleanupTask = () -> {
				if (INSTANCE != null) {
					INSTANCE.closeStaticInstance();
					INSTANCE = null;
				}
			};
			ShutdownHookRegistry.addShutdownHook(cleanupTask,
				ShutdownPriority.DISPOSE_DATABASES.before());
		}
		return INSTANCE;
	}
}
