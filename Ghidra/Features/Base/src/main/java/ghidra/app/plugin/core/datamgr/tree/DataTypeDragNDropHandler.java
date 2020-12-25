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
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask.ActionType;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.task.Task;

public class DataTypeDragNDropHandler implements GTreeDragNDropHandler {
	private static DataFlavor localDataTypeTreeFlavor = createLocalTreeNodeFlavor();

	public static DataFlavor[] allSupportedFlavors = { DataTypeTransferable.localDataTypeFlavor,
		localDataTypeTreeFlavor };

	public static DataFlavor[] builtinFlavors = { DataTypeTransferable.localBuiltinDataTypeFlavor,
		localDataTypeTreeFlavor };

	public static DataFlavor[] restrictedFlavors = { localDataTypeTreeFlavor };

	private final GTree tree;

	private final DataTypeManagerPlugin plugin;

	// create a data flavor that is an List of GTreeNodes
	private static DataFlavor createLocalTreeNodeFlavor() {
		try {
			return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
				"; class=java.util.List", "Local list of Drag/Drop DataType Tree objects");
		}
		catch (Exception e) {
			Msg.showError(DataTypeDragNDropHandler.class, null, null, null, e);
		}
		return null;
	}

	public DataTypeDragNDropHandler(DataTypeManagerPlugin plugin, GTree tree) {
		this.plugin = plugin;
		this.tree = tree;
	}

	@Override
	@SuppressWarnings("unchecked") 	// old API call
	public void drop(GTreeNode destinationNode, Transferable transferable, int dropAction) {
		try {
			List<GTreeNode> list =
				(List<GTreeNode>) transferable.getTransferData(localDataTypeTreeFlavor);
			if (list.contains(destinationNode)) { // don't allow drop on dragged nodes.
				return;
			}
			ActionType actionType =
				dropAction == DnDConstants.ACTION_COPY ? ActionType.COPY : ActionType.MOVE;
			Task task =
				new DataTypeTreeCopyMoveTask(destinationNode, list, actionType,
					(DataTypeArchiveGTree) tree,
					plugin.getConflictHandler());
			plugin.getTool().execute(task, 250);
		}
		catch (UnsupportedFlavorException e) {
			Msg.error(this, "Unable to perform drop operation", e);
		}
		catch (IOException e) {
			Msg.error(this, "Unable to perform drop operation", e);
		}
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
			if (node instanceof ArchiveNode) {
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
			List<?> nodeList = dragUserData;
			ArrayList<ResourceFile> fileList = new ArrayList<ResourceFile>();
			for (Object node : nodeList) {

				ArchiveNode archiveNode = (ArchiveNode) node;
				FileArchive archive = (FileArchive) archiveNode.getArchive();
				ResourceFile file = archive.getFile();
				fileList.add(file);
			}
			return fileList;
		}
		return null;

	}

	@Override
	public boolean isDropSiteOk(GTreeNode destinationNode, DataFlavor[] flavors, int dropAction) {
		// can't drop on the root node
		if (destinationNode == null || destinationNode.getParent() == null) {
			return false;
		}

		// can only drop nodes from other dataTypetrees
		if (!containsFlavor(flavors, localDataTypeTreeFlavor)) {
			return false;
		}

		// destination node must belong to either a modifiable archive or a program archive.
		// i.e. it must be writable.
		ArchiveNode archiveNode = ((DataTypeTreeNode) destinationNode).getArchiveNode();
		if (archiveNode == null || !archiveNode.isModifiable()) {
			return false;
		}

		// only a single datatype node can be dropped on a datatype node.
		if (destinationNode instanceof DataTypeNode) {
			if (!containsFlavor(flavors, DataTypeTransferable.localDataTypeFlavor) &&
				!containsFlavor(flavors, DataTypeTransferable.localBuiltinDataTypeFlavor)) {
				return false;
			}
		}

		if (isDroppingBuiltin(flavors)) {
			if (!isValidBuiltinDropSite(destinationNode)) {
				return false;
			}
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
		return (categoryNode instanceof ArchiveNode);
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
