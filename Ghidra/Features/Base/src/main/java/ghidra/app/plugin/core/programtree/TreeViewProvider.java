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

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedList;

import javax.swing.JComponent;
import javax.swing.event.ChangeEvent;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.services.GoToService;
import ghidra.app.services.ViewManagerService;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * Provides a view of the program tree.
 */
class TreeViewProvider implements ViewProviderService {

	private ProgramTreePanel treePanel;
	private AddressSet view;
	private Program program;
	private GoToService goToService;
	private ViewManagerService viewManagerService;
	private ProgramTreePlugin plugin;

	private final static String NUMBER_OF_GROUPS = "NumberOfGroups";
	private final static String GROUP_NAME = "GroupName";

	private final static int DELAY = 500;

	public TreeViewProvider(String treeName, final ProgramTreePlugin plugin) {

		treePanel = new ProgramTreePanel(treeName, plugin);
		this.plugin = plugin;
		treePanel.addTreeListener(new TreeListener() {
			@Override
			public void treeViewChanged(ChangeEvent e) {
				// notify listeners of view change...
				notifyListeners();
			}

			@Override
			public void goTo(Address addr) {
				goToService.goTo(new AddressFieldLocation(plugin.getCurrentProgram(), addr));
			}
		});
	}

	@Override
	public JComponent getViewComponent() {
		return treePanel;
	}

	@Override
	public String getViewName() {
		return treePanel.getTreeName();
	}

	@Override
	public void setHasFocus(boolean hasFocus) {
		treePanel.setHasFocus(hasFocus);
		plugin.enableActions(program != null);
		if (hasFocus) {
			plugin.treeViewChanged(this);
			if (goToService == null) {
				goToService = plugin.getGoToService();
			}
			if (viewManagerService == null) {
				viewManagerService = plugin.getViewManagerService();
			}
			notifyListeners();
		}
	}

	@Override
	public Object getActivePopupObject(MouseEvent event) {
		return treePanel.prepareSelectionForPopup(event);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext().setContextObject(getActivePopupObject(event));
	}

	@Override
	public Object getActiveObject() {
		return treePanel.getSelectedNode();
	}

	@Override
	public DockingAction[] getToolBarActions() {
		return plugin.getToolBarActions();
	}

	@Override
	public boolean viewClosed() {
		if (program == null) {
			return false;
		}
		if (plugin.closeView(this)) {
			dispose();
			return true;
		}
		return false;
	}

	@Override
	public boolean viewDeleted() {
		if (program == null) {
			return false;
		}
		if (plugin.deleteView(this)) {
			dispose();
			return true;
		}
		return false;
	}

	@Override
	public boolean viewRenamed(String newName) {
		if (program == null) {
			return false;
		}
		if (plugin.renameView(this, newName)) {
			treePanel.setTreeName(newName);
			plugin.reloadTree(treePanel.getDnDTree());
			return true;
		}
		return false;
	}

	@Override
	public AddressSetView addToView(ProgramLocation loc) {
		if (program != null && loc != null && loc.getAddress() != null) {
			addLocationToView(loc);
		}
		else {
			view = new AddressSet();
		}
		return view;

	}

	@Override
	public AddressSetView getCurrentView() {
		return view;
	}

	/////////////////////////////////////////////////////////////////////////

	void selectPathsForLocation(final ProgramLocation loc) {
		RunManager runMgr = plugin.getRunManager();
		runMgr.runNow(new SelectPathsRunnable(program, loc), "Select Fragment for Location", DELAY);
	}

	private void setAncestorList(Group group, LinkedList<String> list,
			ArrayList<LinkedList<String>> pathNameList) {
		ProgramModule root = program.getListing().getRootModule(group.getTreeName());
		ProgramModule[] parents = group.getParents();
		if (parents != null && parents.length > 0) {
			for (ProgramModule parent : parents) {
				LinkedList<String> myList = new LinkedList<>(list);
				myList.addFirst(parent.getName());
				if (parent == root) {
					pathNameList.add(myList);
				}
				else {
					setAncestorList(parent, myList, pathNameList);
				}
			}
		}
	}

	private GroupPath convertToGroupPath(LinkedList<String> list) {
		String[] names = new String[list.size()];
		for (int i = 0; i < list.size(); i++) {
			names[i] = list.get(i);
		}
		return new GroupPath(names);
	}

	/**
	 * Set the name of the view for this provider.
	 * @param newName new name for the view
	 */
	void setViewName(String newName) {
		String oldName = treePanel.getTreeName();
		treePanel.setTreeName(newName);
		// notify the view manager service that the name has changed
		if (viewManagerService == null) {
			viewManagerService = plugin.getViewManagerService();
		}
		viewManagerService.viewNameChanged(this, oldName);
	}

	/**
	 * Release all resources for this provider.
	 */
	void dispose() {
		treePanel.setProgram(null);
		program = null;
		view = null;
		goToService = null;
	}

	/**
	 * Set the program.
	 * @param p program, may be null if the program is closed
	 */
	void setProgram(Program p) {
		if (program == p) {
			return;
		}
		program = p;
		plugin.enableActions(false);
		if (p == null) {
			view = null;
		}
		treePanel.setProgram(p);
		if (program != null) {
			plugin.enableActions(true);
		}
	}

	/**
	 * Set the tree selection.
	 * @param paths the paths to select
	 */
	void setGroupSelection(GroupPath[] paths) {
		treePanel.setGroupSelection(paths);
	}

	void writeDataState(SaveState saveState) {
		GroupView currentView = treePanel.getGroupView();
		String treeName = treePanel.getTreeName();
		int numGroups = currentView.getCount();
		saveState.putInt(NUMBER_OF_GROUPS + treeName, numGroups);
		for (int i = 0; i < numGroups; i++) {
			GroupPath groupPath = currentView.getPath(i);
			String[] path = groupPath.getPath();
			saveState.putStrings(GROUP_NAME + treeName + i, path);
		}
	}

	void readDataState(SaveState saveState) {
		String treeName = treePanel.getTreeName();
		int numGroups = saveState.getInt(NUMBER_OF_GROUPS + treeName, 0);

		GroupPath[] paths = new GroupPath[numGroups];
		for (int i = 0; i < numGroups; i++) {
			String[] path = saveState.getStrings(GROUP_NAME + treeName + i, null);
			if (path == null) {
				numGroups = 0;
				break;
			}
			paths[i] = new GroupPath(path);
		}
		if (numGroups > 0) {
			GroupView newView = new GroupView(paths);
			treePanel.setGroupView(newView);
		}
	}

	/**
	 * Get the program tree object.
	 * @return ProgramDnDTree
	 */
	ProgramDnDTree getProgramDnDTree() {
		return treePanel.getDnDTree();
	}

	AddressSet getView() {
		if (program == null) {
			return new AddressSet();
		}
		AddressSet set = new AddressSet();
		GroupPath[] gp = treePanel.getViewedGroups();
		if (gp == null || program == null) {
			return set;
		}
		String treeName = treePanel.getTreeName();
		for (GroupPath element : gp) {
			Group group = element.getGroup(program, treeName);
			if (group == null) {
				continue;
			}
			// recursively go through module to build up address set
			getAddressSet(group, set);
		}
		return set;
	}

	void replaceView(ProgramNode node) {
		treePanel.replaceView(node);
	}

	/**
	 * Notify listeners that the view map has changed.
	 */
	void notifyListeners() {
		if (plugin.getCurrentProvider() != this) {
			return;
		}
		view = getView();
		plugin.firePluginEvent(
			new ViewChangedPluginEvent(plugin.getName(), treePanel.getTreeName(), view));
	}

	/**
	 * Add to the view the group that corresponds to the address
	 * in the program location.
	 */
	private void addLocationToView(ProgramLocation loc) {
		ProgramFragment fragment =
			program.getListing().getFragment(treePanel.getTreeName(), loc.getAddress());
		if (fragment == null) {
			return;
		}
		LinkedList<String> list = new LinkedList<>();
		list.add(fragment.getName());
		Group group = fragment;
		while (group != null) {
			ProgramModule[] parents = group.getParents();
			group = null;
			if ((parents != null) && (parents.length > 0)) {
				group = parents[0];
				list.addFirst(group.getName());
			}
		}
		String[] groupNames = new String[list.size()];
		list.toArray(groupNames);
		treePanel.addGroupViewPath(new GroupPath(groupNames));
		notifyListeners();
	}

	/**
	 * Get the address set for the given group. If group is a Module, then
	 * recursively call this method for all descendants.
	 * @param group either a Fragment or a Module
	 * @param set address set to populate
	 */
	private void getAddressSet(Group group, AddressSet set) {
		if (group instanceof ProgramFragment) {
			set.add((ProgramFragment) group);
		}
		else {
			Group[] groups = ((ProgramModule) group).getChildren();
			for (Group group2 : groups) {
				getAddressSet(group2, set);
			}
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class SelectPathsRunnable implements SwingRunnable {
		private ProgramLocation loc;
		private GroupPath[] paths;
		private Program myProgram;

		SelectPathsRunnable(Program program, ProgramLocation loc) {
			myProgram = program;
			this.loc = loc;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			if (program == null || program.isClosed()) {
				return;
			}
			try {
				ProgramFragment fragment =
					program.getListing().getFragment(treePanel.getTreeName(), loc.getAddress());
				if (fragment == null) {
					return;
				}
				LinkedList<String> list = new LinkedList<>();
				list.add(fragment.getName());
				Group group = fragment;

				ArrayList<LinkedList<String>> pathNameList = new ArrayList<>();
				// need GroupPath for all occurrences of fragment
				setAncestorList(group, list, pathNameList);

				paths = new GroupPath[pathNameList.size()];
				for (int i = 0; i < paths.length; i++) {
					LinkedList<String> l = pathNameList.get(i);
					paths[i] = convertToGroupPath(l);
				}
			}
			catch (Exception e) {
				if (myProgram == program && program != null && !program.isClosed()) {
					Msg.showError(this, treePanel, "Error Finding Fragments",
						"Could not find fragments for location", e);
				}
			}
		}

		@Override
		public void swingRun(boolean isCancelled) {
			if (isCancelled) {
				return;
			}
			if (paths != null && program != null && !program.isClosed()) {
				setGroupSelection(paths);
			}
		}
	}

}
