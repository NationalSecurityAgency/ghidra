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
/*
 * ModuleSortPlugin.java
 *
 * Created on April 11, 2002, 11:15 AM
 */

package ghidra.app.plugin.core.module;

import java.util.*;

import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.*;

/**
 * Plugin to sort Modules and Fragments within a selected Module.
 * Child Module folders are always name-sorted and placed
 * above child Fragments.  When sorting on address, the minimum
 * address for each fragment is used, while empty fragments are name-sorted
 * and placed at the bottom.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Sort Fragments within Module",
	description = "Plugin to sort Modules and Fragments within a selected Module. " +
			"Child Module folders are always name-sorted and placed " +
			"above child Fragments.  When sorting on address, the minimum " +
			"address for each fragment is used, while empty fragments are name-sorted " +
			" and placed at the bottom."
)
//@formatter:on
public class ModuleSortPlugin extends ProgramPlugin {

	public static final int SORT_BY_NAME = 1;
	public static final int SORT_BY_ADDRESS = 2;

	// Sort by Address Action info
	private final static String[] SORT_BY_ADDR_MENUPATH = new String[] { "Sort", "by Address" };
	private ModuleSortAction sortByAddrAction;

	// Sort by Address Action info
	private final static String[] SORT_BY_NAME_MENUPATH = new String[] { "Sort", "by Name" };
	private ModuleSortAction sortByNameAction;

	public ModuleSortPlugin(PluginTool tool) {
		super(tool, false, false);
		createActions();
	}

	private void createActions() {
		sortByAddrAction =
			new ModuleSortAction("Sort Fragments By Address", getName(), SORT_BY_ADDRESS);
		sortByNameAction = new ModuleSortAction("Sort Fragments By Name", getName(), SORT_BY_NAME);

		tool.addAction(sortByAddrAction);
		tool.addAction(sortByNameAction);
	}

	private void moduleSortCallback(int sortType, Object contextObj) {
		ProgramModule module = getSelectedModule(contextObj);
		if (module == null) {
			return;
		}

		//@formatter:off
		TaskBuilder.withTask(new SortTask(module, sortType))
			.setStatusTextAlignment(SwingConstants.LEADING)
			.launchModal()
			;
		//@formatter:on		
	}

	private void doSort(ProgramModule parent, GroupComparator comparator, TaskMonitor monitor)
			throws NotFoundException, CancelledException {
		List<Group> list = new ArrayList<Group>();
		Group[] kids = parent.getChildren();

		monitor.initialize(kids.length);

		for (Group kid : kids) {
			monitor.checkCanceled();
			list.add(kid);
			if (kid instanceof ProgramModule) {
				doSort((ProgramModule) kid, comparator, monitor);
			}
			monitor.incrementProgress(1);
		}

		Collections.sort(list, comparator);

		monitor.initialize(list.size());
		for (int i = 0; i < list.size(); i++) {
			monitor.checkCanceled();

			Group group = list.get(i);
			monitor.setMessage("processing " + group.getName());
			parent.moveChild(group.getName(), i);
			monitor.incrementProgress(1);

			if (i % 10 == 0) {
				allowSwingThreadToPaintBetweenLongLocking();
			}

		}
	}

	private void allowSwingThreadToPaintBetweenLongLocking() {
		try {
			// In crude testing it seems that just sleeping for the smallest amount of time is
			// enough for the Swing thread to get the lock we usually dominate.  The result is
			// a bit jumpy, but that is better than no painting at all.
			Thread.sleep(100);
		}
		catch (InterruptedException e) {
			// don't care; we tried
		}
	}

	private ProgramModule getSelectedModule(Object contextObj) {
		if (contextObj instanceof ProgramNode) {
			ProgramNode node = (ProgramNode) contextObj;
			if (node.isModule() && node.getTree().getSelectionCount() == 1) {
				return node.getModule();
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class SortTask extends Task {
		private GroupComparator comparator;
		private ProgramModule module;

		SortTask(ProgramModule module, int sortType) {
			super("Sort " + ((sortType == SORT_BY_ADDRESS) ? " by Address" : " by Name"), true,
				true, true, true);
			this.module = module;
			comparator = new GroupComparator(sortType);
		}

		@Override
		public void run(TaskMonitor monitor) {
			int txId = -1;
			boolean success = false;
			try {
				txId = currentProgram.startTransaction(getName());
				doSort(module, comparator, monitor);
				success = true;
			}
			catch (CancelledException ce) {
				// don't care
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Error", "Module Sort Failed", t);
			}
			finally {
				currentProgram.endTransaction(txId, success);
			}
		}
	}

	private class GroupComparator implements Comparator<Group> {
		private int sortType;

		GroupComparator(int sortType) {
			this.sortType = sortType;
		}

		@Override
		public int compare(Group g1, Group g2) {
			if (sortType == SORT_BY_ADDRESS) {
				Address addr1 = null;
				Address addr2 = null;
				if (g1 instanceof ProgramFragment) {
					addr1 = ((ProgramFragment) g1).getMinAddress();
				}
				else {
					ProgramModule m = (ProgramModule) g1;
					addr1 = m.getAddressSet().getMinAddress();
				}
				if (g2 instanceof ProgramFragment) {
					addr2 = ((ProgramFragment) g2).getMinAddress();
				}
				else {
					ProgramModule m = (ProgramModule) g2;
					addr2 = m.getAddressSet().getMinAddress();
				}
				if (addr1 == null && addr2 == null) {
					return 0;
				}
				if (addr1 != null && addr2 == null) {
					return -1;
				}
				if (addr1 == null) {
					return 1;
				}
				return addr1.compareTo(addr2);
			}
			return g1.getName().compareTo(g2.getName());
		}

	}

	class ModuleSortAction extends DockingAction {
		private int sortType;

		public ModuleSortAction(String name, String owner, int sortType) {
			super(name, owner);
			this.sortType = sortType;
			if (sortType == SORT_BY_ADDRESS) {
				setPopupMenuData(new MenuData(SORT_BY_ADDR_MENUPATH, null, "module"));
				setDescription(
					"Perform a minimum address sort of all fragments contained within a selected folder");
			}
			else {
				setPopupMenuData(new MenuData(SORT_BY_NAME_MENUPATH, null, "module"));

				setDescription(
					"Perform a name sort of all fragments contained within a selected folder");
			}
			setEnabled(true); // always enabled
			setHelpLocation(new HelpLocation("ProgramTreePlugin", "SortByAddressOrName"));
		}

		/**
		 * Determine if the Module Sort action should be visible within
		 * the popup menu for the specified active object.
		 * @param context the context
		 * @return true if action should be made visible in popup menu.
		 */
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Object activeObj = context.getContextObject();

			// Only make action available for a single selected Module.
			if (activeObj != null && activeObj instanceof ProgramNode) {
				ProgramNode node = (ProgramNode) activeObj;

				if (node.getProgram() != null && node.isModule() &&
					node.getTree().getSelectionCount() == 1) {
					return true;
				}
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			moduleSortCallback(sortType, context.getContextObject());
		}
	}
}
