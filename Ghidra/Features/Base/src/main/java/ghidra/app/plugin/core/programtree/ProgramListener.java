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
package ghidra.app.plugin.core.programtree;

import java.util.*;

import javax.swing.tree.TreePath;

import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;
import ghidra.util.datastruct.StringKeyIndexer;
import ghidra.util.task.SwingUpdateManager;
import util.CollectionUtils;

/**
 * Listener for the Program domain object; updates the appropriate ProgramDnDTree.
 */
class ProgramListener implements DomainObjectListener {

	private static int THRESHOLD_FOR_RELOAD = 10;
	private ProgramTreeActionManager actionManager;
	private ProgramTreePlugin plugin;
	private ProgramDnDTree tree;
	private SwingUpdateManager updateManager;

	ProgramListener(ProgramTreePlugin plugin) {
		this.plugin = plugin;
		actionManager = plugin.getActionManager();
		updateManager = new SwingUpdateManager(1000, 30000, () -> plugin.reloadProgram(false));
	}

	/**
	 * Interface method called when the program changes.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		update(ev);
	}

	////////////////////////////////////////////////////////////////
	// *** private methods
	////////////////////////////////////////////////////////////////
	/**
	 * Apply the updates that are in the change event.
	 */
	private void update(DomainObjectChangedEvent event) {

		if (willReloadProgram(event)) {
			return;
		}
		boolean viewChanged = false;

		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord rec = event.getChangeRecord(i);

			if (!(rec instanceof ProgramChangeRecord)) {
				continue;
			}
			ProgramChangeRecord record = (ProgramChangeRecord) rec;
			int eventType = rec.getEventType();

			if (eventType == ChangeManager.DOCR_TREE_RENAMED) {
				plugin.treeRenamed((String) record.getOldValue(), (String) record.getNewValue());
			}
			else if (eventType == ChangeManager.DOCR_GROUP_ADDED) {
				processGroupAdded(record);
			}
			else if (eventType == ChangeManager.DOCR_GROUP_REMOVED) {
				processGroupRemoved(record);
			}
			else if (eventType == ChangeManager.DOCR_GROUP_RENAMED) {
				processGroupRenamed(record);
			}
			else if (eventType == ChangeManager.DOCR_MODULE_REORDERED) {
				processModuleReordered(record);
			}
			else if (eventType == ChangeManager.DOCR_GROUP_REPARENTED) {
				processGroupReparented(record);
			}
			else if (eventType == ChangeManager.DOCR_FRAGMENT_MOVED) {
				plugin.fragmentMoved();
			}
			else if (eventType == ChangeManager.DOCR_MEMORY_BLOCKS_JOINED) {
				viewChanged |= processBlockJoined(record);
			}

			if (viewChanged) {
				tree.fireTreeViewChanged();
			}
		}
	}

	/**
	 * Return whether joining blocks has affected the view.
	 */
	private boolean processBlockJoined(ProgramChangeRecord record) {
		tree = plugin.getCurrentProvider().getProgramDnDTree();
		List<TreePath> viewList = tree.getViewList();
		ProgramNode root = (ProgramNode) tree.getModel().getRoot();
		if (viewList.contains(root.getTreePath())) {
			return true;
		}
		Address oldStartAddr = (Address) record.getOldValue();
		return plugin.getView().contains(oldStartAddr);
	}

	/**
	 * Group was reparented.
	 */
	private void processGroupReparented(ProgramChangeRecord record) {
		try {
			Group child = (Group) record.getObject();
			tree = plugin.getTree(child.getTreeName());
			if (tree == null) {
				return;
			}
			synchronized (tree.getModel().getRoot()) {

				String oldParentName = (String) record.getOldValue();
				String newParentName = (String) record.getNewValue();
				String childName = child.getName();
				// save off indexes into the viewList that have matches
				// on [oldParentName] [childName] pair -- will need this to
				// know which path in the viewList that has to be updated...
				int[] viewedIndexes = findViewedIndexes(oldParentName, childName);

				ProgramNode[] nodes = tree.findNodes(childName);
				for (ProgramNode node : nodes) {
					// remove from the tree, but don't affect the view list yet
					tree.groupRemoved(node, oldParentName, false);
				}
				try {
					tree.groupAdded(child, true);
				}
				catch (ArrayIndexOutOfBoundsException e) {
					return; // child index is out of bounds because we
							// have not received all of the events yet
				}

				// now match up the paths in the view with new paths
				nodes = tree.findNodes(childName);
				List<TreePath> viewList = tree.getViewList();
				int idx = 0;
				for (int i = 0; i < nodes.length; i++) {
					if (!nodes[i].getParentModule().getName().equals(newParentName)) {
						continue;
					}
					TreePath nodePath = nodes[i].getTreePath();
					for (int j = idx; j < viewedIndexes.length; j++) {
						TreePath p = nodePath;
						TreePath vp = viewList.get(viewedIndexes[j]);
						ProgramNode programNode = (ProgramNode) vp.getLastPathComponent();
						String vname = programNode.getName();
						if (!vname.equals(childName)) {
							// find descendant with name
							TreePath descPath = findDescendant(nodePath, vname);
							if (descPath != null) {
								viewList.remove(viewedIndexes[j]);
								tree.addToView(p, viewedIndexes[j]);
								++idx;
							}
						}
						else {
							viewList.remove(viewedIndexes[j]);
							tree.addToView(p, viewedIndexes[j]);
							++idx;
						}
					}
				}
				if (childName.equals(actionManager.getLastGroupPasted())) {
					tree.setBusyCursor(false);
				}
				tree.fireTreeViewChanged();
			}

		}
		catch (ConcurrentModificationException e) {
		}
	}

	/**
	 * Group added.
	 */
	private void processGroupAdded(ProgramChangeRecord record) {
		ProgramModule parentModule = (ProgramModule) record.getOldValue();
		tree = plugin.getTree(parentModule.getTreeName());

		if (tree == null) {
			return;
		}
		synchronized (tree.getModel().getRoot()) {
			Group child = (Group) record.getNewValue();

			try {
				tree.groupAdded(child);
			}
			catch (ConcurrentModificationException e) {
				// child no longer exists
				// get another event for group removed as
				// the parent is the child being removed...
				return;
			}
			if (child.getName().equals(actionManager.getLastGroupPasted())) {
				tree.setBusyCursor(false);
			}
		}
	}

	private void processModuleReordered(ProgramChangeRecord record) {
		ProgramModule parent = (ProgramModule) record.getObject();
		tree = plugin.getTree(parent.getTreeName());
		if (tree == null) {
			return;
		}

		synchronized (tree.getModel().getRoot()) {

			Group child = (Group) record.getNewValue();
			TreePath[] selectedPaths = tree.getSelectionPaths();

			tree.reorder(child, parent);
			tree.buildNodeList();
			String childName = child.getName();
			ProgramNode[] nodes = tree.findNodes(childName);

			// restore selection
			tree.addSelectionPaths(selectedPaths);
			if (childName.equals(actionManager.getLastGroupPasted())) {
				tree.setBusyCursor(false);
			}

			List<TreePath> list = tree.getViewList();
			for (ProgramNode node : nodes) {
				if (list.contains(node.getTreePath())) {
					tree.fireTreeViewChanged();
					break;
				}
			}
		}
	}

	/**
	 * A Module or Fragment was renamed, so find all nodes with oldName and update them
	 * with the new name and new Group object.
	 */
	private void processGroupRenamed(ProgramChangeRecord record) {
		Group group = (Group) record.getNewValue();
		String treeName = group.getTreeName();
		tree = plugin.getTree(treeName);
		if (tree == null) {
			return;
		}

		synchronized (tree.getModel().getRoot()) {

			// get expanded descendants so they can be restored to that state after the update

			Enumeration<TreePath> it = tree.getExpandedDescendants(
				((ProgramNode) tree.getModel().getRoot()).getTreePath());

			List<TreePath> expandedPaths = CollectionUtils.asList(it);

			String oldName = (String) record.getOldValue();
			String newName = group.getName();
			Listing listing = tree.getProgram().getListing();
			Group g = listing.getModule(treeName, newName);
			if (g == null) {
				g = listing.getFragment(treeName, newName);
			}

			ProgramNode[] nodes = tree.findNodes(oldName);
			for (ProgramNode node : nodes) {
				node.setName(newName);
				node.setGroup(g);
				tree.updateGroupPath(node);
			}

			tree.expandPaths(expandedPaths);

			// update nameIndexer table
			StringKeyIndexer nameIndexer = tree.getNameIndexer();
			nameIndexer.remove(oldName);
			nameIndexer.put(newName);
		}
	}

	private void processGroupRemoved(ProgramChangeRecord record) {
		try {
			ProgramModule parent = (ProgramModule) record.getOldValue();
			tree = plugin.getTree(parent.getTreeName());

			if (tree == null) {
				return;
			}
			synchronized (tree.getModel().getRoot()) {
				try {
					parent.getName();
				}
				catch (ConcurrentModificationException e) {
					// parent no longer exists, so should
					// get another event for group removed as
					// the parent is the child being removed...
					return;
				}

				String childName = (String) record.getNewValue();

				//find the node for the module
				ProgramNode[] nodes = tree.findNodes(childName);
				for (ProgramNode node : nodes) {
					tree.groupRemoved(node, parent.getName(), true);
				}
				if (childName.equals(actionManager.getLastGroupPasted())) {
					tree.setBusyCursor(false);
				}
				tree.fireTreeViewChanged();
			}

		}
		catch (ConcurrentModificationException e) {
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error processing group removed event", e);
		}
	}

	private boolean willReloadProgram(DomainObjectChangedEvent event) {
		if (updateManager.isBusy()) {
			// TODO does it really make sense to blindly rebuild just because we are rebuilding??  
			// Shouldn't we still use the code below to know updating is needed?
			updateManager.updateLater();
			return true;
		}

		if (rootNameChanged(event)) {
			// major update; rebuild
			updateManager.updateLater();
			return true;
		}

		int changeCnt = 0;
		int recordCount = event.numRecords();
		for (int i = 0; i < recordCount; i++) {
			DomainObjectChangeRecord rec = event.getChangeRecord(i);
			int eventType = rec.getEventType();
			if (eventType == DomainObject.DO_OBJECT_RESTORED ||
				eventType == ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) {
				// for object restored, check the root node to see if it is invalid; 
				// otherwise for memory block removed, rebuild the tree
				plugin.reloadProgram(eventType == DomainObject.DO_OBJECT_RESTORED);
				return true;
			}
			if (eventType == ChangeManager.DOCR_GROUP_ADDED ||
				eventType == ChangeManager.DOCR_GROUP_REMOVED ||
				eventType == ChangeManager.DOCR_FRAGMENT_MOVED ||
				eventType == ChangeManager.DOCR_MODULE_REORDERED) {
				changeCnt++;
			}
			else if (eventType == ChangeManager.DOCR_TREE_REMOVED) {
				plugin.treeRemoved((String) rec.getOldValue());
			}
			else if (eventType == ChangeManager.DOCR_TREE_CREATED) {
				plugin.treeViewAdded((String) rec.getNewValue());
			}
		}

		if (changeCnt > THRESHOLD_FOR_RELOAD) {
			updateManager.updateLater();
			return true;
		}

		return false;
	}

	private boolean rootNameChanged(DomainObjectChangedEvent event) {
		Program sourceProgram = (Program) event.getSource();
		if (plugin.getCurrentProgram() != sourceProgram) { // yes '=='
			// the plugin's active program is not changed
			return false;
		}

		return event.containsEvent(ChangeManager.DOCR_TREE_RENAMED) ||
			event.containsEvent(DomainObject.DO_OBJECT_RENAMED);
	}

	private int[] findViewedIndexes(String oldParentName, String childName) {

		List<TreePath> viewList = tree.getViewList();
		int[] indexes = new int[viewList.size()];
		int idx = 0;

		for (int i = 0; i < viewList.size(); i++) {
			TreePath path = viewList.get(i);
			String[] names = getNames(path);
			for (int j = 0; j < names.length; j++) {
				if (names[j].equals(childName) && j > 0 && names[j - 1].equals(oldParentName)) {
					indexes[idx] = i;
					++idx;
					break;
				}
			}
		}
		if (idx <= indexes.length - 1) {
			int[] temp = new int[idx];
			for (int i = 0; i < idx; i++) {
				temp[i] = indexes[i];
			}
			indexes = temp;
		}
		return indexes;
	}

	private String[] getNames(TreePath path) {

		int count = path.getPathCount();
		String[] names = new String[count];

		for (int i = 0; i < count; i++) {
			ProgramNode node = (ProgramNode) path.getPathComponent(i);
			names[i] = node.getName();
		}
		return names;
	}

	private TreePath findDescendant(TreePath path, String name) {
		ProgramNode node = (ProgramNode) path.getLastPathComponent();
		if (node.getName().equals(name)) {
			return node.getTreePath();
		}

		if (node.getAllowsChildren() && !node.wasVisited()) {
			tree.visitNode(node);
		}
		for (int i = 0; i < node.getChildCount(); i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			TreePath p = findDescendant(child.getTreePath(), name);
			if (p != null) {
				return p;
			}
		}
		return null;
	}

	void dispose() {
		updateManager.dispose();
	}
}
