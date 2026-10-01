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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import docking.dnd.GenericDataFlavor;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.util.DataTypesCopyMoveTask;
import ghidra.app.plugin.core.datamgr.util.DataTypesCopyMoveTask.ActionType;
import ghidra.program.database.dtarchive.FileDtArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.util.Msg;

public class DataTypeDragNDropHandler implements GTreeDragNDropHandler {

	/** A list of GTree nodes from the Data Type tree */
	private static DataFlavor localDataTypeTreeFlavor = createLocalTreeNodeFlavor();

	private static DataFlavor[] allSupportedFlavors =
		{ DataTypeTransferable.localDataTypeFlavor, localDataTypeTreeFlavor,
			DataTypeTransferable.localDataTypeListFlavor };
	private static DataFlavor[] builtinFlavors =
		{ DataTypeTransferable.localBuiltinDataTypeFlavor, localDataTypeTreeFlavor };
	private static DataFlavor[] restrictedFlavors = { localDataTypeTreeFlavor };

	private final GTree tree;

	private final DataTypeManagerPlugin plugin;

	// create a data flavor that is an List of GTreeNodes
	private static DataFlavor createLocalTreeNodeFlavor() {
		return new GenericDataFlavor(
			DataFlavor.javaJVMLocalObjectMimeType + "; class=java.util.List",
			"Local list of Drag/Drop DataType Tree objects");
	}

	public DataTypeDragNDropHandler(DataTypeManagerPlugin plugin, GTree tree) {
		this.plugin = plugin;
		this.tree = tree;
	}

	@Override
	@SuppressWarnings("unchecked") 	// getTransferData(); old API call
	public void drop(GTreeNode destinationNode, Transferable transferable, int dropAction) {

		try {
			if (transferable.isDataFlavorSupported(localDataTypeTreeFlavor)) {
				List<GTreeNode> nodes =
					(List<GTreeNode>) transferable.getTransferData(localDataTypeTreeFlavor);
				dropDtNodes(destinationNode, nodes, dropAction);
				return;
			}

			if (transferable.isDataFlavorSupported(DataTypeTransferable.localDataTypeListFlavor)) {
				List<DataType> types = (List<DataType>) transferable.getTransferData(
					DataTypeTransferable.localDataTypeListFlavor);
				dropTypes(destinationNode, types, dropAction);
				return;
			}

			Msg.error(this, "Unable to perform drop operation");
		}
		catch (IOException | UnsupportedFlavorException e) {
			Msg.error(this, "Unable to perform drop operation", e);
		}
	}

	private void dropTypes(GTreeNode destinationNode, List<DataType> types, int dropAction) {

		CategoryNode updatedDestinationNode = getDropTargetNode(destinationNode);
		Category destination = updatedDestinationNode.getCategory();
		DataTypeManager dtm = destination.getDataTypeManager();
		DataTypeStore dataStore = dtm.getDataStore();
		ActionType actionType =
			dropAction == DnDConstants.ACTION_COPY ? ActionType.COPY : ActionType.MOVE;
		DataTypesCopyMoveTask task =
			new DataTypesCopyMoveTask(plugin, dataStore, destination, types, List.of(), actionType);

		plugin.getTool().execute(task, 250);
	}

	private void dropDtNodes(GTreeNode destinationNode, List<GTreeNode> nodes, int dropAction) {
		if (nodes.contains(destinationNode)) { // don't allow drop on dragged nodes.
			return;
		}

		CategoryNode updatedDestinationNode = getDropTargetNode(destinationNode);
		Category destination = updatedDestinationNode.getCategory();
		ActionType actionType =
			dropAction == DnDConstants.ACTION_COPY ? ActionType.COPY : ActionType.MOVE;
		DataTypesCopyMoveTask task =
			DataTypesCopyMoveTask.forNodes(plugin, tree, destination, nodes, actionType);

		plugin.getTool().execute(task, 250);
	}

	private CategoryNode getDropTargetNode(GTreeNode node) {

		// clients can drop/paste onto a category or archive
		if (node instanceof CategoryNode) {
			return (CategoryNode) node;
		}

		return (CategoryNode) node.getParent();
	}

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> draggedNodes) {
		// single, datatype node supports both datatype dragging *and* local tree dragging
		if (draggedNodes.size() == 1) {
			GTreeNode node = draggedNodes.get(0);
			if (node instanceof DataTypeNode) {
				DataType dataType = ((DataTypeNode) node).getDataType();

				if (dataType instanceof BuiltInDataType ||
					dataType instanceof MissingBuiltInDataType) {
					return builtinFlavors;
				}
				return allSupportedFlavors;
			}

			// we don't support dragging archives in their entirety
			if (node instanceof DataTypeStoreNode) {
				return new DataFlavor[] {};
			}
		}

		// multiple nodes or non-datatype nodes restrict dragging to local tree dragging
		return restrictedFlavors;
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_COPY_OR_MOVE;
	}

	@Override
	public Object getTransferData(List<GTreeNode> dragUserData, DataFlavor flavor) {
		if (flavor.equals(DataTypeTransferable.localDataTypeFlavor) ||
			flavor.equals(DataTypeTransferable.localBuiltinDataTypeFlavor)) {
			// we know from getSupportedDataFlavors() that this is a single DataTypeNode
			DataTypeNode dataTypeNode = (DataTypeNode) dragUserData.get(0);
			return dataTypeNode.getDataType();
		}
		else if (flavor.equals(localDataTypeTreeFlavor)) {
			return dragUserData;
		}
		else if (flavor.equals(DataFlavor.javaFileListFlavor)) {
			List<GTreeNode> nodeList = dragUserData;
			ArrayList<ResourceFile> fileList = new ArrayList<ResourceFile>();
			for (Object node : nodeList) {
				if (node instanceof FileArchiveNode fileArchiveNode) {
					FileDtArchiveDB archive = (FileDtArchiveDB) fileArchiveNode.getArchive();
					ResourceFile file = archive.getFile();
					fileList.add(file);
				}
			}
			return fileList;
		}
		return null;

	}

	@Override
	public boolean isDropSiteOk(GTreeNode destinationNode, DataFlavor[] flavors, int dropAction) {

		if (!isValidDataTypeDestination(destinationNode, flavors, dropAction)) {
			return false;
		}

		GTreeNode updatedDestinationNode = getDropTargetNode(destinationNode);

		if (isDroppingBuiltin(flavors)) {
			if (!isValidBuiltinDropSite(updatedDestinationNode)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Verifies the given destination node can accept the given drop/copy/paste action and content
	 * flavors.
	 * @param destinationNode the node accepting the action
	 * @param flavors the supported flavors of the action
	 * @param dropAction the actual action see {@link DnDConstants}
	 * @return true if valid
	 */
	public boolean isValidDataTypeDestination(GTreeNode destinationNode, DataFlavor[] flavors,
			int dropAction) {
		// can't drop/paste on the root node
		if (destinationNode == null || destinationNode.getParent() == null) {
			return false;
		}

		// destination node must belong to either a modifiable archive or a program archive.
		// i.e. it must be writable.
		DataTypeStoreNode archiveNode = ((DataTypeTreeNode) destinationNode).getArchiveNode();
		if (archiveNode == null || !archiveNode.isModifiable()) {
			return false;
		}

		// dropping from a data types table
		if (containsFlavor(flavors, DataTypeTransferable.localDataTypeListFlavor)) {
			return true;
		}

		// drop/paste nodes from other dataType trees
		if (!containsFlavor(flavors, localDataTypeTreeFlavor)) {
			return false;
		}

		return true;
	}

	private boolean isDroppingBuiltin(DataFlavor[] flavors) {
		for (DataFlavor flavor : flavors) {
			if (flavor.equals(DataTypeTransferable.localBuiltinDataTypeFlavor)) {
				return true;
			}
		}
		return false;
	}

	private boolean isValidBuiltinDropSite(GTreeNode destinationNode) {
		if (!(destinationNode instanceof CategoryNode)) {
			return true;
		}
		CategoryNode categoryNode = (CategoryNode) destinationNode;
		return (categoryNode instanceof DataTypeStoreNode);
	}

	private boolean containsFlavor(DataFlavor[] flavors, DataFlavor flavor) {
		for (DataFlavor f : flavors) {
			if (f.equals(flavor)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
		return true;
	}
}
