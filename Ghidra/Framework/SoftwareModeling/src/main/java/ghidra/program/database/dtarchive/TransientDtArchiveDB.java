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

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.data.TransientDataTypeManager;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.dtarchive.TransientDataTypeArchive;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link PersistentDataTypeArchive} that is meant to be used by clients as a temporary scratch pad for
 * exploring datatype relationships without polluting the program's data type manager or any
 * persistent datatype archive.
 */
public class TransientDtArchiveDB extends DataTypeArchiveDB implements TransientDataTypeArchive {

	private TransientDataTypeManager dtm;

	public TransientDtArchiveDB(DBHandle dbHandle, String name, TransientDataTypeManager dtm)
			throws IOException {
		this.dtm = dtm;
		super(dbHandle, name, new Object());
	}

	@Override
	protected TransientDataTypeManager createDataTypeManager(DBHandle handle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		if (openMode != OpenMode.CREATE) {
			throw new IllegalArgumentException("only create is supported");
		}
		return dtm; // use instance specified with TransientDtArchiveDB constructor
	}

	@Override
	public TransientDataTypeManager getDataTypeManager() {
		return (TransientDataTypeManager) super.getDataTypeManager();
	}

	@Override
	public String getDescription() {
		return "Transient Data Type Archive";
	}

	@Override
	public void close() {
		// Expose method to TransientDataTypeManager
		super.close();
	}

	@Override
	public boolean isTemporary() {
		return true;
	}

	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.TEMPORARY;
	}

}
