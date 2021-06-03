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
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class DisassociateAction extends DockingAction {
	public static final String MENU_NAME = "Disassociate Datatypes From";

	private final SourceArchive sourceArchive;
	private final DataTypeManager dtm;
	private final DataTypeManagerHandler handler;
	private final DataTypeManagerPlugin plugin;
	private final ArchiveNode archiveNode;

	public DisassociateAction(DataTypeManagerPlugin plugin, DataTypeManagerHandler handler,
			DataTypeManager dtm, ArchiveNode archiveNode, SourceArchive sourceArchive) {
		super("Disassociate Archive", plugin.getName());
		this.plugin = plugin;
		this.handler = handler;
		this.dtm = dtm;
		this.archiveNode = archiveNode;
		this.sourceArchive = sourceArchive;
		setPopupMenuData(new MenuData(new String[] { MENU_NAME, sourceArchive.getName() }));
		setHelpLocation(new HelpLocation(plugin.getName(), "Disassociate_Data_Types"));

	}

	private boolean isPreselectedForAction(DataTypeSyncInfo dataTypeSyncInfo) {
		return dataTypeSyncInfo.getSyncState() == DataTypeSyncState.ORPHAN;
	}

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

		List<DataTypeSyncInfo> allAssociatedTypes = synchronizer.findAssociatedDataTypes();
		if (allAssociatedTypes.isEmpty()) {
			synchronizer.removeSourceArchive();
			showNoAssociationsMessage(synchronizer);
			return;
		}

		Set<DataTypeSyncInfo> preselectedInfos = getPreselectedInfos(allAssociatedTypes);
		List<DataTypeSyncInfo> typesToDisassociate =
			getSelectedDataTypes(synchronizer, allAssociatedTypes, preselectedInfos);
		if (typesToDisassociate.isEmpty()) {
			return;
		}

		if (!confirmOperation(typesToDisassociate)) {
			return;
		}

		//@formatter:off
		MonitoredRunnable r = 
			monitor -> doDisassociate(synchronizer, typesToDisassociate, allAssociatedTypes, monitor);
		new TaskBuilder("Disassociate From Archive", r)
			.setStatusTextAlignment(SwingConstants.LEADING)
			.launchModal()
			;		
		//@formatter:on
	}

	private void doDisassociate(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> typesToDisassociate, List<DataTypeSyncInfo> associatedDataTypes,
			TaskMonitor monitor) {

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
		tree.collapseAll(archiveNode);

		try {
			disassociateTypes(synchronizer, typesToDisassociate, associatedDataTypes, monitor);
		}
		catch (CancelledException e) {
			// nothing to report
		}
		finally {
			tree.restoreTreeState(treeState);
		}
	}

	private void showNoAssociationsMessage(DataTypeSynchronizer synchronizer) {
		String source = synchronizer.getSourceName();
		String client = synchronizer.getClientName();
		Msg.showInfo(getClass(), plugin.getTool().getToolFrame(), "No Associations Found",
			"No associated datatypes found for archive \"" + source + "\"\nRemoving \"" + source +
				"\" information from \"" + client + "\".");

	}

	private Set<DataTypeSyncInfo> getPreselectedInfos(List<DataTypeSyncInfo> all) {
		Set<DataTypeSyncInfo> set = new HashSet<>();
		for (DataTypeSyncInfo dataTypeSyncInfo : all) {
			if (isPreselectedForAction(dataTypeSyncInfo)) {
				set.add(dataTypeSyncInfo);
			}
		}
		return set;
	}

	private void disassociateTypes(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> typesToDisassociate, List<DataTypeSyncInfo> allAssociatedTypes,
			TaskMonitor monitor) throws CancelledException {

		synchronizer.openTransactions();
		try {

			monitor.initialize(typesToDisassociate.size());
			for (DataTypeSyncInfo info : typesToDisassociate) {
				monitor.checkCanceled();
				monitor.setMessage("Disassociating " + info.getName());
				info.disassociate();
				monitor.incrementProgress(1);
			}
			if (typesToDisassociate.size() == allAssociatedTypes.size()) {
				synchronizer.removeSourceArchive();
			}

		}
		finally {
			synchronizer.closeTransactions();
		}
	}

	private boolean confirmOperation(List<DataTypeSyncInfo> selectedList) {
		String message = "This will <b>permanently</b> disassociate these datatypes" +
			" from the archive.<br><br>Are you sure you want to <b><u>disassociate</u></b> " +
			selectedList.size() + " datatype(s)?";
		String asHtml = HTMLUtilities.wrapAsHTML(message);
		int result = OptionDialog.showYesNoDialog(plugin.getTool().getToolFrame(),
			"Confirm Disassociate", asHtml);
		return result == OptionDialog.YES_OPTION;
	}

	private void showRequiresArchiveOpenMessage(String archiveName) {
		Msg.showError(getClass(), plugin.getTool().getToolFrame(), "Disassociate Failed",
			"Archive \"" + archiveName + "\" must be open for editing.");
	}

	private List<DataTypeSyncInfo> getSelectedDataTypes(DataTypeSynchronizer synchronizer,
			List<DataTypeSyncInfo> all, Set<DataTypeSyncInfo> preselectedInfos) {

		String clientName = synchronizer.getClientName();
		String sourceName = synchronizer.getSourceName();
		DataTypeSyncDialog dialog = new DataTypeSyncDialog(plugin, clientName, sourceName, all,
			preselectedInfos, "Disassociate", getTitle(sourceName, clientName));
		dialog.setHelpLocation(new HelpLocation(plugin.getName(), "Disassociate_Data_Types"));

		plugin.getTool().showDialog(dialog);

		return dialog.getSelectedInfos();
	}

	private String getTitle(String sourceName, String clientName) {
		return "Disassociate Datatype In \"" + clientName + "\" From Archive \"" + sourceName +
			"\"";
	}

	protected boolean containsConflicts(List<DataTypeSyncInfo> infos) {
		for (DataTypeSyncInfo dataTypeSyncInfo : infos) {
			if (dataTypeSyncInfo.getSyncState() == DataTypeSyncState.CONFLICT) {
				return true;
			}
		}
		return false;
	}
}
