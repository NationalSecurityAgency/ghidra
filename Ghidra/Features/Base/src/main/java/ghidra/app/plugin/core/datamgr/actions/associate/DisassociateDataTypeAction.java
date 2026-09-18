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
package ghidra.app.plugin.core.datamgr.actions.associate;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class DisassociateDataTypeAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public DisassociateDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Disassociate From Archive", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Disassociate From Archive" }, null, "Sync"));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypeContext dtc)) {
			return false;
		}

		return dtc.hasSelectedDataTypes();
	}

	private List<DataType> getDisassociatableTypes(DataTypeContext dtc) {
		List<DataType> result = new ArrayList<>();
		List<DataType> types = dtc.getSelectedDataTypes();
		for (DataType dt : types) {
			if (isDisassociatable(dt)) {
				result.add(dt);
			}
		}
		return result;
	}

	private boolean isDisassociatable(DataType dt) {
		DataTypeManager dataTypeManager = dt.getDataTypeManager();
		SourceArchive sourceArchive = dt.getSourceArchive();
		if (sourceArchive == null || dataTypeManager == null ||
			sourceArchive.equals(BuiltInSourceArchive.INSTANCE) ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {
			return false;
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeContext dtc = (DataTypeContext) context;
		List<DataType> types = getDisassociatableTypes(dtc);

		if (types.isEmpty()) {
			Msg.showInfo(this, null, "No Disassociatable Types Selected",
				"No disassociatable types selected");
			return;
		}

		//@formatter:off
		Optional<DataTypeManager> unmodifiableDtm = types
			.stream()
		    .map(dt -> dt.getDataTypeManager())
		    .filter(dtm -> !dtm.isUpdatable())
		    .findAny();
		//@formatter:on

		if (unmodifiableDtm.isPresent()) {
			DataTypeManager dtm = unmodifiableDtm.get();
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(context.getSourceComponent(),
				"Disassociate Failed", dtm);
			return;
		}

		if (!confirmOperation(types.size())) {
			return;
		}

		//@formatter:off
		MonitoredRunnable r =
			monitor -> doDisassociate(types, monitor);
		new TaskBuilder("Disassociate From Archive", r)
			.setStatusTextAlignment(SwingConstants.LEADING)
			.launchModal();
		//@formatter:on
	}

	private boolean confirmOperation(int size) {
		String message = "This will <b>permanently</b> disassociate these datatypes" +
			" from the archive.<br><br>Are you sure you want to <b><u>disassociate</u></b> " +
			size + " datatype(s)?";
		String asHtml = HTMLUtilities.wrapAsHTML(message);
		int result = OptionDialog.showYesNoDialog(plugin.getTool().getToolFrame(),
			"Confirm Disassociate", asHtml);
		return result == OptionDialog.YES_OPTION;
	}

	private void collapseArchiveNodes(DataTypeArchiveGTree tree) {
		// Note: collapsing archive nodes will actually remove all the children of the archive
		//       which means no event processing and less memory consumption.
		GTreeNode root = tree.getViewRoot();
		List<GTreeNode> archives = root.getChildren();
		archives.forEach(archive -> tree.collapseAll(archive));
	}

	private void doDisassociate(List<DataType> types, TaskMonitor monitor) {

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

		collapseArchiveNodes(tree);

		try {
			disassociateTypes(types, monitor);
		}
		catch (CancelledException e) {
			// nothing to report
		}
		finally {
			tree.restoreTreeState(treeState);
		}
	}

	private void disassociateTypes(List<DataType> dataTypes, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(dataTypes.size());

		//@formatter:off
		Map<DataTypeManager, List<DataType>> managersToTypes =
			dataTypes.stream()
				     .collect(
				    	     Collectors.groupingBy(dt -> dt.getDataTypeManager()))
				     ;
		//@formatter:on

		for (Entry<DataTypeManager, List<DataType>> entry : managersToTypes.entrySet()) {
			DataTypeManager dtm = entry.getKey();
			List<DataType> types = entry.getValue();
			disassociateManagersTypes(dtm, types, monitor);
		}
	}

	private void disassociateManagersTypes(DataTypeManager dtm, List<DataType> dataTypes,
			TaskMonitor monitor) throws CancelledException {

		// we must process these by their source

		//@formatter:off
		Map<SourceArchive, List<DataType>> sourceToTypes =
			dataTypes.stream()
					 .collect(
					     Collectors.groupingBy(dt -> dt.getSourceArchive()))
					 ;
		//@formatter:on

		monitor.setMessage("Disassociating types from " + dtm.getName());
		monitor.initialize(dataTypes.size());
		ArchiveManager archiveManager = plugin.getArchiveManager();
		for (Entry<SourceArchive, List<DataType>> entry : sourceToTypes.entrySet()) {
			SourceArchive source = entry.getKey();
			List<DataType> types = entry.getValue();
			DataTypeSynchronizer synchronizer =
				new DataTypeSynchronizer(archiveManager, dtm, source);
			disassociate(synchronizer, dtm, types, monitor);
		}
	}

	private void disassociate(DataTypeSynchronizer synchronizer, DataTypeManager dtm,
			List<DataType> types, TaskMonitor monitor) throws CancelledException {

		int txId = dtm.startTransaction(getName());
		try {
			for (DataType dt : types) {
				monitor.checkCancelled();
				monitor.setMessage("Disassociating " + dt.getName());
				dtm.disassociate(dt);
				monitor.incrementProgress(1);
			}

			synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}
}
