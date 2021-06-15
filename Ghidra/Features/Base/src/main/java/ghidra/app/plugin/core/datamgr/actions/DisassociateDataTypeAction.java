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
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.swing.SwingConstants;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
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
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		List<DataTypeNode> nodes = getDisassociatableNodes(selectionPaths);
		return !nodes.isEmpty();
	}

	private List<DataTypeNode> getDisassociatableNodes(TreePath[] paths) {

		List<DataTypeNode> nodes = new ArrayList<>();
		for (TreePath treePath : paths) {
			DataTypeNode node = getDisassociatableNode(treePath);
			if (node != null) {
				nodes.add(node);
			}
		}
		return nodes;
	}

	private DataTypeNode getDisassociatableNode(TreePath path) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}

		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		if (sourceArchive == null || dataTypeManager == null ||
			sourceArchive.equals(BuiltInSourceArchive.INSTANCE) ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {

			return null;
		}
		return dataTypeNode;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		List<DataTypeNode> nodes = getDisassociatableNodes(selectionPaths);

		//@formatter:off
		Optional<DataTypeManager> unmodifiableDtm = nodes
			.stream()
		    .map(node -> {
				DataType dataType = node.getDataType();
				DataTypeManager dtm = dataType.getDataTypeManager();
				return dtm;
		    })
		    .filter(dtm -> {
		     	return !dtm.isUpdatable();
		    })
		    .findAny();
		//@formatter:on

		if (unmodifiableDtm.isPresent()) {
			DataTypeManager dtm = unmodifiableDtm.get();
			DataTypeUtils.showUnmodifiableArchiveErrorMessage(gTree, "Disassociate Failed", dtm);
			return;
		}

		if (!confirmOperation(nodes)) {
			return;
		}

		//@formatter:off
		MonitoredRunnable r = 
			monitor -> doDisassociate(nodes, monitor);
		new TaskBuilder("Disassociate From Archive", r)
			.setStatusTextAlignment(SwingConstants.LEADING)
			.launchModal();		
		//@formatter:on
	}

	private boolean confirmOperation(List<DataTypeNode> nodes) {
		String message = "This will <b>permanently</b> disassociate these datatypes" +
			" from the archive.<br><br>Are you sure you want to <b><u>disassociate</u></b> " +
			nodes.size() + " datatype(s)?";
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

	private void doDisassociate(List<DataTypeNode> nodes, TaskMonitor monitor) {

		List<DataType> dataTypes =
			nodes.stream().map(node -> node.getDataType()).collect(Collectors.toList());

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
			disassociateTypes(dataTypes, monitor);
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
		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		for (Entry<SourceArchive, List<DataType>> entry : sourceToTypes.entrySet()) {
			SourceArchive source = entry.getKey();
			List<DataType> types = entry.getValue();
			DataTypeSynchronizer synchronizer = new DataTypeSynchronizer(handler, dtm, source);
			disassociate(synchronizer, dtm, types, monitor);
		}
	}

	private void disassociate(DataTypeSynchronizer synchronizer, DataTypeManager dtm,
			List<DataType> types, TaskMonitor monitor) throws CancelledException {

		synchronizer.openTransactions();
		try {
			for (DataType dt : types) {
				monitor.checkCanceled();
				monitor.setMessage("Disassociating " + dt.getName());
				dtm.disassociate(dt);
				monitor.incrementProgress(1);
			}

			synchronizer.reSyncOutOfSyncInTimeOnlyDataTypes();
		}
		finally {
			synchronizer.closeTransactions();
		}
	}
}
