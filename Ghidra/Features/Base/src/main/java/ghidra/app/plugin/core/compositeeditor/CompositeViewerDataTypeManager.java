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
import java.util.Iterator;
import java.util.TreeSet;

import javax.help.UnsupportedOperationException;

import db.util.ErrorHandler;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

/**
 * {@link CompositeViewerDataTypeManager} provides a data type manager that the structure editor 
 * will use internally for updating the structure being edited and tracks all directly and 
 * indirectly referenced datatypes.  This manager also facilitates undo/redo support within
 * the editor.
 * @param <T> Specific {@link Composite} type being managed
 */
public class CompositeViewerDataTypeManager<T extends Composite> extends StandAloneDataTypeManager
		implements ErrorHandler {

	/** 
	 * The data type manager for original composite data type being edited.
	 * This is where the edited datatype will be written back to.
	 */
	private final DataTypeManager originalDTM;
	private final T originalComposite; // may be null if not resolved into this DTM
	private final T viewComposite;  // may be null if not resolved into this DTM

	// Database-backed datatype ID map, view to/from original DTM
	// This is needed to account for datatype use and ID alterations across undo/redo
	private final IDMapDB dataTypeIDMap;

	// Editor transaction use only - undo/redo not supported if restoreCallback is null
	private Callback restoredCallback;
	private Callback changeCallback;
	private int transactionId = 0;
	private boolean dataTypeChanged;

	// Modification count used to signal optional clearing of undo/redo stack at the end of a
	// transaction should any database modifications occur.
	private long flattenModCount = -1;

	// datatype IDs to be checked as orphaned.
	// NOTE: Orphan removal can only be done when this DTM actively manages the viewComposite
	private TreeSet<Long> orphanIds = new TreeSet<>();

	/**
	 * Creates a data type manager that the composite editor will use internally for managing 
	 * dependencies without resolving the actual composite being edited.  A single transaction 
	 * will be started with this instantiation and held open until this instance is closed.  
	 * Undo/redo and datatype pruning is not be supported.
	 * @param rootName the root name for this data type manager (usually the program name).
	 * @param originalDTM the original data type manager.
	 */
	public CompositeViewerDataTypeManager(String rootName, DataTypeManager originalDTM) {
		this(rootName, originalDTM, null, null, null);
		transactionId = startTransaction("Composite Edit");
	}

	/**
	 * Creates a data type manager that the structure editor will use internally for managing a 
	 * structure being edited and its dependencies.
	 * @param rootName the root name for this data type manager (usually the program name).
	 * @param originalComposite the original composite data type that is being edited.
	 * @param changeCallback Callback will be invoked when any change is made to the view composite.
	 * @param restoredCallback Callback will be invoked following any undo/redo.
	 */
	public CompositeViewerDataTypeManager(String rootName, T originalComposite,
			Callback changeCallback, Callback restoredCallback) {
		this(rootName, originalComposite.getDataTypeManager(), originalComposite, changeCallback,
			restoredCallback);
	}

	/**
	 * Constructor
	 * @param rootName the root name for this data type manager (usually the program name).
	 * @param originalDTM the original datatype manager
	 * @param originalComposite the original composite data type that is being edited. (may be null)
	 * @param changeCallback Callback will be invoked when any change is made to the view composite.
	 * @param restoredCallback Callback will be invoked following any undo/redo.
	 */
	private CompositeViewerDataTypeManager(String rootName, DataTypeManager originalDTM,
			T originalComposite, Callback changeCallback, Callback restoredCallback) {
		super(rootName, originalDTM.getDataOrganization());
		this.originalDTM = originalDTM;
		this.originalComposite = originalComposite;
		this.changeCallback = changeCallback;
		this.restoredCallback = restoredCallback;

		int txId = startTransaction("Setup for Edit");
		try {
			initializeArchitecture();
			dataTypeIDMap = new IDMapDB(dbHandle, this);
			viewComposite = resolveViewComposite();
		}
		finally {
			endTransaction(txId, true);
		}
		clearUndo();
	}

	@SuppressWarnings("unchecked")
	private T resolveViewComposite() {
		return originalComposite != null ? (T) super.resolve(originalComposite, null) : null;
	}

	private void initializeArchitecture() {
		ProgramArchitecture arch = originalDTM.getProgramArchitecture();
		if (arch != null) {
			try {
				setProgramArchitecture(arch, null, true, TaskMonitor.DUMMY);
			}
			catch (CancelledException e) {
				throw new AssertException(e); // unexpected
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}
	}

	/**
	 * Provides a means of detecting changes to the underlying database during a transaction.
	 * @return current modification count
	 */
	public long getModCount() {
		return dbHandle.getModCount();
	}

	@Override
	protected synchronized void clearUndo() {
		// Exposes method for test use
		super.clearUndo();
	}

	@Override
	public void undo() {
		if (!isUndoRedoAllowed()) {
			throw new UnsupportedOperationException();
		}
		dataTypeIDMap.invalidate();
		super.undo();
	}

	@Override
	public void redo() {
		if (!isUndoRedoAllowed()) {
			throw new UnsupportedOperationException();
		}
		dataTypeIDMap.invalidate();
		super.redo();
	}

	/**
	 * Return the view composite
	 * @return view composite or null if not resolved during instantiation.
	 */
	public T getResolvedViewComposite() {
		return viewComposite;
	}

	/**
	 * Determine if undo/redo is allowed.
	 * @return true if undo/redo is allowed with use of individual transactions, else false
	 */
	public boolean isUndoRedoAllowed() {
		return restoredCallback != null;
	}

	@Override
	protected final boolean isArchitectureChangeAllowed() {
		return false;
	}

	@Override
	public synchronized void close() {
		if (transactionId != 0) {
			super.endTransaction(transactionId, true);
		}
		super.close();
	}

	/**
	 * Get the {@link DataTypeManager} associated with the original composite datatype being edited.
	 * @return original datatype manager
	 */
	public DataTypeManager getOriginalDataTypeManager() {
		return originalDTM;
	}

	@Override
	public ArchiveType getType() {
		return originalDTM.getType();
	}

	@Override
	public boolean allowsDefaultBuiltInSettings() {
		return originalDTM.allowsDefaultBuiltInSettings();
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
		if (dataType == originalComposite && viewComposite != null) {
			// be sure to resolve use of original composite (e.g., pointer use)
			// from program/archive to view instance.  The viewComposite will
			// be null while resolving it during instantiation of this
			// DataTypeManager instance.
			return viewComposite;
		}
		DataType resolvedDt = super.resolve(dataType, handler);
		if ((dataType instanceof DatabaseObject) && originalDTM.contains(dataType)) {
			long originalId = originalDTM.getID(dataType);
			long myId = getID(resolvedDt);
			dataTypeIDMap.put(myId, originalId);
		}
		return resolvedDt;
	}

	@Override
	public DataType replaceDataType(DataType existingViewDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {

		if (existingViewDt.getDataTypeManager() != this) {
			throw new IllegalArgumentException("datatype is not from this manager");
		}

		if (existingViewDt instanceof DatabaseObject) {
			dataTypeIDMap.remove(getID(existingViewDt));
		}

		DataType newResolvedDt =
			super.replaceDataType(existingViewDt, replacementDt, updateCategoryPath);

		if (newResolvedDt instanceof DatabaseObject &&
			replacementDt.getDataTypeManager() == originalDTM) {
			long originalId = originalDTM.getID(replacementDt);
			long myId = getID(newResolvedDt);
			dataTypeIDMap.put(myId, originalId);
		}

		return newResolvedDt;
	}

	@Override
	public boolean remove(DataType existingViewDt, TaskMonitor monitor) {

		if (existingViewDt.getDataTypeManager() != this) {
			throw new IllegalArgumentException("datatype is not from this manager");
		}

		if (existingViewDt instanceof DatabaseObject) {
			dataTypeIDMap.remove(getID(existingViewDt));
		}

		return super.remove(existingViewDt, monitor);
	}

	/**
	 * Refresh all datatypes which originate from the originalDTM.
	 * This methods is intended for use following an undo/redo of the originalDTM only
	 * and will purge the ID mappings for any datatypes which no longer exist or become
	 * orphaned.
	 * @return true if a dependency change is detected, else false
	 */
	public boolean refreshDBTypesFromOriginal() {
		synchronized (orphanIds) {
			return withTransaction("DataTypes Restored", () -> {
				boolean changed = false;
				clearUndoOnChange();
				Iterator<DataType> allDataTypes = getAllDataTypes();
				while (allDataTypes.hasNext()) {
					DataType dt = allDataTypes.next();
					if (dt == viewComposite || !(dt instanceof DatabaseObject)) {
						continue;
					}

					// subject all DB types to orphan check
					long myId = getID(dt);
					if (viewComposite != null) {
						orphanIds.add(myId);
					}

					Long originalId = dataTypeIDMap.getOriginalIDFromViewID(myId);
					if (originalId == null) {
						continue;
					}

					DataType originalDt = originalDTM.getDataType(originalId);
					if (originalDt == null) {
						changed = true;
						remove(dt, TaskMonitor.DUMMY);
						continue;
					}

					if (!originalDt.isEquivalent(dt)) {
						changed = true;
						try {
							originalDt = replaceDataType(dt, originalDt, true);
						}
						catch (DataTypeDependencyException e) {
							throw new AssertException(e); // should not occur
						}
					}

					CategoryPath path = dt.getCategoryPath();
					if (!originalDt.getCategoryPath().equals(path)) {
						Category newDtCat = createCategory(path);
						try {
							newDtCat.moveDataType(dt, null);
						}
						catch (DataTypeDependencyException e) {
							throw new AssertException(e); // should not occur
						}
					}

				}
				checkOrphansForRemoval(true);
				return changed;
			});
		}
	}

	@Override
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		super.dataTypeChanged(dt, isAutoChange);
		if (dt == viewComposite) {
			// Set dataTypeChanged which will trigger changeCallback when transaction fully comitted
			dataTypeChanged = true;
		}
	}

	@Override
	public void notifyRestored() {
		super.notifyRestored();
		if (restoredCallback != null) {
			Swing.runLater(() -> restoredCallback.call());
		}
	}

	@Override
	public synchronized boolean endTransaction(int transactionID, boolean commit) {

		if (viewComposite != null && getTransactionCount() == 1) {
			// Perform orphan removal only at the end of the outer-most transaction
			synchronized (orphanIds) {
				checkOrphansForRemoval(false);
			}
		}

		boolean committed = super.endTransaction(transactionID, commit);

		if (!isTransactionActive() && flattenModCount != -1) {
			if (flattenModCount != dbHandle.getModCount()) {
				// Mod count differs from flagged mod count - clean undo/redo
				clearUndo();
			}
			flattenModCount = -1;
		}

		if (committed && dataTypeChanged && changeCallback != null) {
			Swing.runLater(() -> changeCallback.call());
		}

		if (getTransactionCount() == 0) {
			dataTypeChanged = false;
		}

		return committed;
	}

	private void checkOrphansForRemoval(boolean cleanupIdMaps) {
		while (!orphanIds.isEmpty()) {
			long id = orphanIds.removeFirst();
			if (!hasParent(id)) {
				DataType dt = getDataType(id);
				if (dt instanceof DatabaseObject) {

					if (dt == viewComposite) {
						continue;
					}

					// check all children of the datatype which may become orphaned
					orphanIds.addAll(getChildIds(id));

					// Remove orphan DB datatype
					remove(dt, TaskMonitor.DUMMY);

					if (cleanupIdMaps) {
						dataTypeIDMap.remove(id);
					}
				}
			}
		}
	}

	/**
	 * Flag the next transaction end to check for subsequent database modifications 
	 * and clear undo/redo stack if changes are detected.  This call is ignored if 
	 * there is already a pending check.
	 */
	public synchronized void clearUndoOnChange() {
		if (flattenModCount == -1) {
			flattenModCount = dbHandle.getModCount();
		}
	}

	@Override
	protected void removeParentChildRecord(long parentID, long childID) {
		// assume lock is in use
		super.removeParentChildRecord(parentID, childID);

		if (viewComposite != null) {
			synchronized (orphanIds) {
				if (!hasParent(childID)) {
					// assumes if parent is removed it will not be re-added durig same transaction
					orphanIds.add(childID);
				}
			}
		}
	}

	/**
	 * Find a resolved DB-datatype within this manager based upon its source datatype's ID 
	 * within the original datatype manager associated with this manager.  This method is 
	 * useful when attempting to matchup a datatype within this manager to one which has changed
	 * within the original datatype manager.
	 * 
	 * @param originalId datatype ID within original datatype manager
	 * @return matching DB-datatype or null if not found
	 */
	public DataType findMyDataTypeFromOriginalID(long originalId) {
		Long myId = dataTypeIDMap.getViewIDFromOriginalID(originalId);
		return myId != null ? getDataType(myId) : null;
	}

	/**
	 * Find a resolved DB-datatype within the original datatype manager based upon a resolved 
	 * datatype's ID within this manager. This method is useful when attempting to matchup a 
	 * datatype within this manager to one which has possibly changed within the original 
	 * datatype manager.
	 * 
	 * @param myId resolved datatype ID within this datatype manager
	 * @return matching DB-datatype or null if not found
	 */
	public DataType findOriginalDataTypeFromMyID(long myId) {
		Long originalId = dataTypeIDMap.getOriginalIDFromViewID(myId);
		return originalId != null ? originalDTM.getDataType(originalId) : null;
	}

	/**
	 * Determine if the specified datatype which has previsouly been resolved to this datatype
	 * manager originated from original composite's source (e.g., program).  
	 * <P>
	 * NOTE: Non-DB datatypes will always return false.
	 * 
	 * @param existingViewDt existing datatype which has previously been resolved to this
	 * datatype manager.
	 * @return true if specified datatype originated from this manager's associated original 
	 * datatype manager.
	 */
	public boolean isViewDataTypeFromOriginalDTM(DataType existingViewDt) {
		if (existingViewDt.getDataTypeManager() != this) {
			throw new IllegalArgumentException("datatype is not from this manager");
		}
		if (!(existingViewDt instanceof DatabaseObject)) {
			return false;
		}
		return dataTypeIDMap.getOriginalIDFromViewID(getID(existingViewDt)) != null;
	}

}
