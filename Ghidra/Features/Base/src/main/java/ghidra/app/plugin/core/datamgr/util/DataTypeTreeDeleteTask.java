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
package ghidra.app.plugin.core.datamgr.util;

import java.util.*;
import java.util.Map.Entry;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DataTypeTreeDeleteTask extends Task {

	// if the total number of nodes is small, we won't need to collapse the tree before deleting
	// the nodes to avoid excess tree events
	private static final int NODE_COUNT_FOR_COLLAPSING_TREE = 100;
	private Map<ArchiveNode, List<GTreeNode>> nodesByArchive;
	private DataTypeManagerPlugin plugin;
	private int nodeCount;

	private boolean hasClosedCategories = false;

	public DataTypeTreeDeleteTask(DataTypeManagerPlugin plugin, List<GTreeNode> nodes) {
		super("Delete Nodes", true, true, true);
		this.plugin = plugin;
		nodeCount = nodes.size();
		nodes = filterList(nodes);

		nodesByArchive = groupNodeByArchive(nodes);
	}

	private Map<ArchiveNode, List<GTreeNode>> groupNodeByArchive(List<GTreeNode> nodes) {

		Map<ArchiveNode, List<GTreeNode>> archiveNodeMap = new HashMap<>();
		for (GTreeNode node : nodes) {
			ArchiveNode archiveNode = ((DataTypeTreeNode) node).getArchiveNode();
			List<GTreeNode> archiveNodeList = archiveNodeMap.computeIfAbsent(archiveNode,
				n -> new ArrayList<>());

			if (node instanceof CategoryNode) {
				if (!node.isLoaded()) {
					hasClosedCategories = true;
				}
			}

			archiveNodeList.add(node);
		}
		return archiveNodeMap;
	}

	private List<GTreeNode> filterList(List<GTreeNode> nodeList) {
		Set<GTreeNode> nodeSet = new HashSet<>(nodeList);
		List<GTreeNode> filteredList = new ArrayList<>();

		for (GTreeNode node : nodeSet) {
			if (!containsAncestor(nodeSet, node)) {
				filteredList.add(node);
			}
		}

		return filteredList;
	}

	private boolean containsAncestor(Set<GTreeNode> nodeSet, GTreeNode node) {
		GTreeNode parent = node.getParent();
		if (parent == null) {
			return false;
		}

		if (nodeSet.contains(parent)) {
			return true;
		}

		return containsAncestor(nodeSet, parent);
	}

	@Override
	public void run(TaskMonitor monitor) {

		int total = 0;
		for (List<GTreeNode> list : nodesByArchive.values()) {
			total += list.size();
		}

		monitor.initialize(total);

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
		boolean collapseTree = nodeCount > NODE_COUNT_FOR_COLLAPSING_TREE || hasClosedCategories;
		Program program = plugin.getProgram();
		boolean wereEventsEnabled = program.isSendingEvents();
		try {
			program.setEventsEnabled(false);

			if (collapseTree) {
				monitor.setIndeterminate(true);
				collapseArchives(tree);
			}

			Set<Entry<ArchiveNode, List<GTreeNode>>> entries = nodesByArchive.entrySet();
			for (Entry<ArchiveNode, List<GTreeNode>> entry : entries) {
				List<GTreeNode> list = entry.getValue();
				ArchiveNode node = entry.getKey();
				deleteNodes(node, list, monitor);
			}
		}
		catch (CancelledException e) {
			// nothing to report
		}
		finally {

			// Allow any events to go out before we restore the tree state so that the tree does 
			// not have to process any events it is not concerned with.
			program.flushEvents();
			program.getDataTypeManager().flushEvents();
			program.setEventsEnabled(wereEventsEnabled);
			if (collapseTree) {
				Swing.allowSwingToProcessEvents();
				tree.restoreTreeState(treeState);
			}
		}
	}

	private void collapseArchives(DataTypeArchiveGTree tree) {
		GTreeNode root = tree.getModelRoot();
		List<GTreeNode> children = root.getChildren();
		for (GTreeNode archive : children) {
			tree.collapseAll(archive);
		}
	}

	private void deleteNodes(ArchiveNode archiveNode, List<GTreeNode> list, TaskMonitor monitor)
			throws CancelledException {

		Archive archive = archiveNode.getArchive();
		DataTypeManager dtm = archive.getDataTypeManager();
		dtm.withTransaction("Delete Category/DataType", () -> {
			for (GTreeNode node : list) {
				monitor.checkCancelled();
				removeNode(node, monitor);
				monitor.incrementProgress(1);
			}
		});
	}

	private void removeNode(GTreeNode node, TaskMonitor monitor) {
		if (node instanceof DataTypeNode) {
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();
			dataTypeManager.remove(dataType);
		}
		else {
			CategoryNode categoryNode = (CategoryNode) node;
			Category category = categoryNode.getCategory();
			category.getParent().removeCategory(category.getName(), monitor);
		}
	}
}
