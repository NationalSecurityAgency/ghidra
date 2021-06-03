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
package ghidra.app.plugin.core.datamgr.actions;

import java.util.*;

import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public abstract class SyncAction extends DockingAction implements Comparable<SyncAction> {

	private final SourceArchive sourceArchive;
	private final DataTypeManager dtm;
	private final DataTypeManagerHandler handler;
	private final DataTypeManagerPlugin plugin;
	private final ArchiveNode archiveNode;

	SyncAction(String name, DataTypeManagerPlugin plugin, DataTypeManagerHandler handler,
			DataTypeManager dtm, ArchiveNode archiveNode, SourceArchive sourceArchive,
			boolean isEnabled) {
		super(name, plugin.getName());
		this.plugin = plugin;
		this.handler = handler;
		this.dtm = dtm;
		this.archiveNode = archiveNode;
		this.sourceArchive = sourceArchive;
		setEnabled(isEnabled);
	}

	protected abstract int getMenuOrder();

	protected abstract boolean isAppropriateForAction(DataTypeSyncInfo info);

	protected abstract boolean isPreselectedForAction(DataTypeSyncInfo dataTypeSyncInfo);

	protected abstract String getOperationName();

	protected abstract void applyOperation(DataTypeSyncInfo info);

	protected abstract String getConfirmationMessage(List<DataTypeSyncInfo> selectedInfos);

	protected abstract boolean requiresArchiveOpenForEditing();

	protected abstract String getTitle(String sourceName, String clientName);

	protected abstract String getHelpTopic();

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypeSynchronizer synchronizer = new DataTypeSynchronizer(handler, dtm, sourceArchive);

		if (!dtm.isUpdatable()) {
			showRequiresArchiveOpenMessage(dtm.getName());
			return;
		}

		DataTypeManager sourceDTM = handler.getDataTypeManager(sourceArchive);
		if (sourceDTM == null) {
			Msg.showInfo(getClass(), plugin.getTool().getToolFrame(),
				"Cannot Access Source Archive",
				"Can't access the data types for the " + sourceArchive.getName() + " archive.");
			return;
		}

		if (requiresArchiveOpenForEditing() && !sourceDTM.isUpdatable()) {
			showRequiresArchiveOpenMessage(sourceArchive.getName());
			return;
		}

		//@formatter:off
		TaskBuilder.withTask(new SyncTask(synchronizer))
			.setStatusTextAlignment(SwingConstants.LEADING)
			.launchModal()
			;
		//@formatter:on
	}

	private void doSync(DataTypeSynchronizer synchronizer, TaskMonitor monitor) {

		//
		// Note: we collapse the node before performing this work because there is a 
		//       potential for a large number of events to be generated.  Further, if the
		//       given archive node has many children (like 10s of thousands), then the
		//       copious events generated herein could lock the UI.  By closing the node, 
		//       the tree is not invalidating/validating its cache as a result of these
		//       events.
		//
		DataTypesProvider provider = plugin.getProvider();
		DataTypeArchiveGTree tree = provider.getGTree();
		GTreeState treeState = tree.getTreeState();
		try {
			tree.collapseAll(archiveNode);

			monitor.setMessage("Finding out-of-sync types");
			Set<DataTypeSyncInfo> outOfSynchDataTypes =
				new HashSet<>(synchronizer.findOutOfSynchDataTypes());

			removeAndUpdateOutOfSyncInTimeOnlyDataTypes(synchronizer, outOfSynchDataTypes);
			if (outOfSynchDataTypes.isEmpty()) {
				showNoDataTypesToSyncMessage();
				return;
			}

			List<DataTypeSyncInfo> filteredList = filterList(outOfSynchDataTypes);
			if (filteredList.isEmpty()) {
				showNoDataTypesForThisOperationMessage(sourceArchive.getName(),
					outOfSynchDataTypes);
				return;
			}

			Set<DataTypeSyncInfo> preselectedInfos = getPreselectedInfos(filteredList);
			List<DataTypeSyncInfo> selectedList =
				getSelectedDataTypes(synchronizer, filteredList, preselectedInfos);
			if (selectedList.isEmpty()) {
				return;
			}

			if (!confirmOperation(selectedList)) {
				return;
			}

			monitor.initialize(selectedList.size());
			processSelectedDataTypes(synchronizer, selectedList, outOfSynchDataTypes, monitor);

			Set<DataTypeSyncInfo> outOfSynchDataTypesAfterProcessed =
				new HashSet<>(synchronizer.findOutOfSynchDataTypes());

			reportAnyLeftOverOutOfSyncDataTypes(sourceArchive.getName(),
				outOfSynchDataTypesAfterProcessed);
		}
		catch (CancelledException e) {
			// nothing to report
		}
		finally {
			tree.restoreTreeState(treeState);
		}
	}

	private Set<DataTypeSyncInfo> getPreselectedInfos(List<DataTypeSyncInfo> list) {
		Set<DataTypeSyncInfo> set = new HashSet<>();
		for (DataTypeSyncInfo dataTypeSyncInfo : list) {
			if (isPreselectedForAction(dataTypeSyncInfo)) {
				set.add(dataTypeSyncInfo);
			}
		}
		return set;
	}

	private void reportAnyLeftOverOutOfSyncDataTypes(String archiveName,
			Set<DataTypeSyncInfo> outOfSynchDataTypes) {
		if (outOfSynchDataTypes.isEmpty()) {
			return;
		}
		String status = getStatusMessage(outOfSynchDataTypes);
		Msg.showInfo(getClass(), plugin.getTool().getToolFrame(),
			"Archive \"" + archiveName + "\" Not Synchronized",
			"There are still datatypes that are out of sync!\n\n" + status);

	}

	private void processSelectedDataTypes(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> selectedList, Set<DataTypeSyncInfo> outOfSynchDataTypes,
			TaskMonitor monitor) throws CancelledException {

		synchronizer.openTransactions();
		try {
			for (DataTypeSyncInfo info : selectedList) {
				monitor.checkCanceled();
				monitor.setMessage("Syncing " + info.getName());
				applyOperation(info);
				outOfSynchDataTypes.remove(info);
				monitor.incrementProgress(1);
			}

			// dataTypeChanged can cause other related data types to become updated
			// and their times will appear out of sync. So clean up any that actually
			// are the same.
			Set<DataTypeSyncInfo> outOfSynchDataTypesAfterProcessed =
				new HashSet<>(synchronizer.findOutOfSynchDataTypes());
			removeAndUpdateOutOfSyncInTimeOnlyDataTypes(synchronizer,
				outOfSynchDataTypesAfterProcessed);
			if (outOfSynchDataTypesAfterProcessed.isEmpty()) {
				synchronizer.markSynchronized();
			}

		}
		finally {
			synchronizer.closeTransactions();
		}
	}

	private boolean confirmOperation(List<DataTypeSyncInfo> selectedList) {
		int result = OptionDialog.showYesNoDialog(plugin.getTool().getToolFrame(),
			"Confirm " + getOperationName(), getConfirmationMessage(selectedList));
		return result == OptionDialog.YES_OPTION;
	}

	private List<DataTypeSyncInfo> getSelectedDataTypes(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> filteredList, Set<DataTypeSyncInfo> preselectedInfos) {

		String clientName = synchronizer.getClientName();
		String sourceName = synchronizer.getSourceName();
		DataTypeSyncDialog dialog = new DataTypeSyncDialog(plugin, clientName, sourceName,
			filteredList, preselectedInfos, getOperationName(), getTitle(sourceName, clientName));
		dialog.setHelpLocation(new HelpLocation(plugin.getName(), getHelpTopic()));
		plugin.getTool().showDialog(dialog);

		return dialog.getSelectedInfos();
	}

	private void showNoDataTypesForThisOperationMessage(String archiveName,
			Set<DataTypeSyncInfo> outOfSyncInfos) {
		String status = getStatusMessage(outOfSyncInfos);
		Msg.showInfo(getClass(), plugin.getTool().getToolFrame(), "No Data Type Changes",
			"No datatypes found to " + getOperationName() + " for archive \"" + archiveName +
				"\".\n\n" + status);
	}

	private void showRequiresArchiveOpenMessage(String archiveName) {
		Msg.showError(getClass(), plugin.getTool().getToolFrame(), getOperationName() + " Failed",
			"Archive \"" + archiveName + "\" must be open for editing.");
	}

	private String getStatusMessage(Set<DataTypeSyncInfo> outOfSyncInfos) {
		int orphanCount = 0;
		int conflictCount = 0;
		int updateCount = 0;
		int commitCount = 0;
		for (DataTypeSyncInfo info : outOfSyncInfos) {
			switch (info.getSyncState()) {
				case COMMIT:
					commitCount++;
					break;
				case CONFLICT:
					conflictCount++;
					break;
				case ORPHAN:
					orphanCount++;
					break;
				case UPDATE:
					updateCount++;
				case IN_SYNC:
				case UNKNOWN:
			}
		}
		StringBuffer buf = new StringBuffer();
		if (updateCount > 0) {
			buf.append("\nNumber of UPDATES remaining:   " + updateCount);
		}
		if (commitCount > 0) {
			buf.append("\nNumber of COMMITS remaining:   " + commitCount);
		}
		if (conflictCount > 0) {
			buf.append("\nNumber of CONFLICTS remaining: " + conflictCount);
		}
		if (orphanCount > 0) {
			buf.append("\nNumber of ORPHANS remaining:   " + orphanCount);
		}

		return buf.toString();
	}

	private void showNoDataTypesToSyncMessage() {
		Msg.showInfo(getClass(), plugin.getTool().getToolFrame(), "No Data Type Changes",
			"No out of sync datatypes found. Updating sync time.");
	}

	@Override
	public int compareTo(SyncAction o) {
		return getMenuOrder() - o.getMenuOrder();
	}

	protected List<DataTypeSyncInfo> filterList(Set<DataTypeSyncInfo> allOutOfSyncDataTypes) {
		List<DataTypeSyncInfo> filteredList = new ArrayList<>();
		for (DataTypeSyncInfo dataTypeSyncInfo : allOutOfSyncDataTypes) {
			if (isAppropriateForAction(dataTypeSyncInfo)) {
				filteredList.add(dataTypeSyncInfo);
			}
		}
		return filteredList;
	}

	/**
	 * Checks if datatype is really out of sync or only is is marked as out of sync but really
	 * is not changed.  If datatypes are really in sync, updates the time marks to indicate that
	 * they are in sync;
	 * @param outOfSynchDataTypes list of all datatypes that are marked as "out of sync".
	 */
	private void removeAndUpdateOutOfSyncInTimeOnlyDataTypes(DataTypeSynchronizer synchronizer,
			Set<DataTypeSyncInfo> outOfSynchDataTypes) {
		List<DataTypeSyncInfo> list = new ArrayList<>();

		Iterator<DataTypeSyncInfo> iterator = outOfSynchDataTypes.iterator();
		while (iterator.hasNext()) {
			DataTypeSyncInfo dataTypeSyncInfo = iterator.next();
			if (!dataTypeSyncInfo.hasChange()) {
				list.add(dataTypeSyncInfo);
				iterator.remove();
			}
		}
		autoUpdateDataTypesThatHaveNoRealChanges(synchronizer, list, outOfSynchDataTypes.isEmpty());
	}

	private void autoUpdateDataTypesThatHaveNoRealChanges(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> outOfSynchInTimeOnlyList, boolean markArchiveSynchronized) {

		int transactionID = dtm.startTransaction("auto sync datatypes");
		try {
			for (DataTypeSyncInfo dataTypeSyncInfo : outOfSynchInTimeOnlyList) {
				dataTypeSyncInfo.syncTimes();
			}
			if (markArchiveSynchronized) {
				synchronizer.markSynchronized();
			}
		}
		finally {
			dtm.endTransaction(transactionID, true);
		}
	}

	protected boolean containsConflicts(List<DataTypeSyncInfo> infos) {
		for (DataTypeSyncInfo dataTypeSyncInfo : infos) {
			if (dataTypeSyncInfo.getSyncState() == DataTypeSyncState.CONFLICT) {
				return true;
			}
		}
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** Task for off-loading long-running Sync operation */
	private class SyncTask extends Task {

		private DataTypeSynchronizer synchronizer;

		public SyncTask(DataTypeSynchronizer synchronizer) {
			super("Data Type Sync - " + getOperationName(), true, true, true);
			this.synchronizer = synchronizer;
		}

		@Override
		public void run(TaskMonitor monitor) {
			doSync(synchronizer, monitor);
		}

	}

}
