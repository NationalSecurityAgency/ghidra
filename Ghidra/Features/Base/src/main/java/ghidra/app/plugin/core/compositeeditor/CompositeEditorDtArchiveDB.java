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
package ghidra.app.plugin.core.compositeeditor;

import java.io.IOException;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.dtarchive.DataTypeArchiveDB;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

/**
 * DataTypeAchive used to edit composites (unions or structures)
 *
 * @param <T> The specific type of composite
 */
public class CompositeEditorDtArchiveDB<T extends Composite> extends DataTypeArchiveDB {
	private int transactionId;

	/**
	 * Special constructor for stack editor. We create a transaction that is always open for the
	 * life of this archive so that undo/redo is not available.
	 * @param originalDTM the data type manager this archive is shadowing.
	 * @throws IOException if an {@link IOException} occurs initializing the database.
	 */
	CompositeEditorDtArchiveDB(DataTypeManager originalDTM) throws IOException {
		this(originalDTM, null, null, null);

		// This prevents undo/redo by always have a transaction open during its full lifecycle.
		transactionId = startTransaction("Composite Edit");
	}

	public CompositeEditorDtArchiveDB(T originalComposite, Callback changeCallback,
			Callback restoredCallback) throws IOException {
		this(originalComposite.getDataTypeManager(), originalComposite, changeCallback,
			restoredCallback);
	}

	protected CompositeEditorDtArchiveDB(DataTypeManager originalDTM, T originalComposite,
			Callback changeCallback,
			Callback restoredCallback) throws IOException {
		super(new DBHandle(), originalDTM.getName(), new Object());
		CompositeViewerDataTypeManager<T> dtm = getDataTypeManager();
		withTransaction("Setup for Edit", () -> {
			dtm.intialize(originalDTM, originalComposite, changeCallback, restoredCallback);
		});
		clearUndo();
	}

	@SuppressWarnings("unchecked")
	@Override
	public CompositeViewerDataTypeManager<T> getDataTypeManager() {
		return (CompositeViewerDataTypeManager<T>) super.getDataTypeManager();
	}

	@Override
	protected CompositeViewerDataTypeManager<T> createDataTypeManager(DBHandle handle,
			OpenMode openMode, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		return new CompositeViewerDataTypeManager<>(handle, openMode, this, lock, monitor);
	}

	@Override
	public boolean isTemporary() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Temporary Data Type Archive For Composite Editing";
	}

	@Override
	protected boolean isArchitectureChangeAllowed() {
		return false;
	}

	@Override
	protected void close() {
		if (transactionId != 0) {
			endTransaction(transactionId, changed);
		}
		super.close();
	}

	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.TEMPORARY;
	}

}
