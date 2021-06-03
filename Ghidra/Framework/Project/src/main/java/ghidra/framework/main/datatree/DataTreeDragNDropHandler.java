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
package ghidra.framework.main.datatree;

import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import docking.dnd.GenericDataFlavor;
import docking.tool.ToolConstants;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import ghidra.framework.main.FrontEndTool;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public class DataTreeDragNDropHandler implements GTreeDragNDropHandler {
	private static Map<DataFlavor, DataTreeFlavorHandler> activeProjectDropFlavorHandlerMap =
		new HashMap<>();
	public static DataFlavor localDomainFileTreeFlavor = createLocalTreeNodeFlavor();

	public static DataFlavor localDomainFileFlavor = createLocalTreeFlavor();
	public static DataFlavor[] allSupportedFlavors =
		{ localDomainFileTreeFlavor, localDomainFileFlavor, DataFlavor.stringFlavor };

	// create a data flavor that is an List of GTreeNodes
	private static DataFlavor createLocalTreeNodeFlavor() {
		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.util.List",
				"Local list of Drag/Drop Project Domain Tree objects");
		}
		catch (Exception e) {
			Msg.showError(DataTreeDragNDropHandler.class, null, null, null, e);
		}
		return null;
	}

	private static DataFlavor createLocalTreeFlavor() {
		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.util.List",
				"Local list of Drag/Drop Project Domain objects");
		}
		catch (Exception e) {
			Msg.showError(DataTreeDragNDropHandler.class, null, null, null, e);
		}
		return null;
	}

	private boolean isActiveProject;
	private final FrontEndTool tool;
	private final DataTree tree;

	DataTreeDragNDropHandler(FrontEndTool tool, DataTree tree, boolean isActiveProject) {
		this.tool = tool;
		this.tree = tree;
		this.isActiveProject = isActiveProject;
	}

	@Override
	public void drop(GTreeNode destination, Transferable transferable, int dropAction) {
		DataFlavor[] transferDataFlavors = transferable.getTransferDataFlavors();
		for (DataFlavor dataFlavor : transferDataFlavors) {
			DataTreeFlavorHandler flavorHandler = getFlavorHandler(dataFlavor);
			if (flavorHandler != null) {
				handleDrop(destination, transferable, dropAction, dataFlavor, flavorHandler);
				return;
			}
		}
	}

	private void handleDrop(GTreeNode destination, Transferable transferable, int dropAction,
			DataFlavor dataFlavor, DataTreeFlavorHandler flavorHandler) {

		try {
			Object transferData = transferable.getTransferData(dataFlavor);
			flavorHandler.handle(tool, tree, destination, transferData, dropAction);
		}
		catch (UnsupportedFlavorException e) {
			throw new AssertException("Got unsupported flavor from using a supported flavor");
		}
		catch (IOException e) {
			Msg.showError(this, null, "IO Error", "Error during drop", e);
		}
	}

	private DataTreeFlavorHandler getFlavorHandler(DataFlavor flavor) {
		return activeProjectDropFlavorHandlerMap.get(flavor);
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_COPY_OR_MOVE;
	}

	@Override
	public boolean isDropSiteOk(GTreeNode destUserData, DataFlavor[] flavors, int dropAction) {
		if (!isActiveProject) {
			return false;
		}
		if (ToolConstants.NO_ACTIVE_PROJECT.equals(destUserData.getName())) {
			return false;
		}

		return true;
	}

	@Override
	public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
		for (GTreeNode gTreeNode : dragUserData) {
			if (gTreeNode.getParent() != null) {
				return true;
			}
		}
		return false;
	}

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes) {
		return allSupportedFlavors;
	}

	@Override
	public Object getTransferData(List<GTreeNode> transferNodes, DataFlavor flavor)
			throws UnsupportedFlavorException {

		if (flavor == localDomainFileTreeFlavor) {
			// this removes files that are already in the list because they are children of
			// folders that are in the list
			return removeDuplicates(transferNodes);
		}
		else if (flavor == localDomainFileFlavor) {
			// filter for file nodes and convert each node to its corresponding domainFile
			return transferNodes.stream()
					.filter(DomainFileNode.class::isInstance)
					.map(node -> ((DomainFileNode) node).getDomainFile())
					.collect(Collectors.toList());
		}
		else if (flavor.equals(DataFlavor.stringFlavor)) {
			// allow users to copy the names of nodes
			return transferNodes.stream()
					.map(node -> node.getName())
					.collect(Collectors.joining("\n"));
		}
		throw new AssertException("Called with a flavor that we didn't say we supported");
	}

	private List<GTreeNode> removeDuplicates(List<GTreeNode> allNodes) {

		List<GTreeNode> folderNodes = getDomainFolderNodes(allNodes);

		// if a file has a parent in the list, then it is not needed as a separate entry
		return allNodes.stream()
				.filter(node -> !isChildOfFolders(folderNodes, node))
				.collect(Collectors.toList());
	}

	private List<GTreeNode> getDomainFolderNodes(List<GTreeNode> nodeList) {
		List<GTreeNode> folderList = new ArrayList<>();

		for (GTreeNode node : nodeList) {
			if (node instanceof DomainFolderNode) {
				folderList.add(node);
			}
		}

		return folderList;
	}

	private boolean isChildOfFolders(List<GTreeNode> folderNodes, GTreeNode fileNode) {
		GTreeNode node = fileNode.getParent();
		while (node != null) {
			if (folderNodes.contains(node)) {
				return true;
			}
			node = node.getParent();
		}
		return false;
	}

	public static void addActiveDataFlavorHandler(DataFlavor flavor,
			DataTreeFlavorHandler handler) {
		activeProjectDropFlavorHandlerMap.put(flavor, handler);
	}

	public static DataTreeFlavorHandler removeActiveDataFlavorHandler(DataFlavor flavor) {
		return activeProjectDropFlavorHandlerMap.remove(flavor);
	}

	public void setProjectActive(boolean b) {
		isActiveProject = b;
	}
}
