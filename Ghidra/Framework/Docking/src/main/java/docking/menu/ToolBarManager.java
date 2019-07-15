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
package docking.menu;

import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.action.DockingActionIf;
import docking.action.ToolBarData;
import docking.widgets.VariableHeightPanel;

/**
 * Manages the actions to be displayed in the toolbar.  Organizes them by group.
 */
public class ToolBarManager {
	private Map<String, List<ToolBarItemManager>> groupToItemsMap =
		new TreeMap<>(new GroupComparator());
	private Comparator<? super ToolBarItemManager> toolBarItemComparator =
		new ToolBarItemManagerComparator();

	private volatile JComponent toolBar;
	private final DockingWindowManager windowManager;

	public ToolBarManager(DockingWindowManager windowManager) {
		this.windowManager = windowManager;
	}

	public void clearActions() {
		groupToItemsMap.clear();
		toolBar = null;
	}

	public void addAction(DockingActionIf action) {
		ToolBarData toolBarData = action.getToolBarData();
		if (toolBarData == null) {
			return;
		}

		toolBar = null; // invalidate the current toolbar

		String group = toolBarData.getToolBarGroup();
		List<ToolBarItemManager> items = groupToItemsMap.get(group);
		if (items == null) {
			items = new ArrayList<>();
			groupToItemsMap.put(group, items);
		}
		items.add(new ToolBarItemManager(action, windowManager));

		Collections.sort(items, toolBarItemComparator);
	}

	public DockingActionIf getAction(String actionName) {
		Collection<List<ToolBarItemManager>> values = groupToItemsMap.values();
		for (List<ToolBarItemManager> list : values) {
			for (ToolBarItemManager manager : list) {
				DockingActionIf action = manager.getAction();
				if (actionName.equals(action.getName())) {
					return action;
				}
			}
		}
		return null;
	}

	/**
	 * Releases all resources.  Makes this object unusable.
	 */
	public void dispose() {
		Set<Entry<String, List<ToolBarItemManager>>> entrySet = groupToItemsMap.entrySet();
		for (Entry<String, List<ToolBarItemManager>> entry : entrySet) {
			List<ToolBarItemManager> items = entry.getValue();
			for (ToolBarItemManager item : items) {
				item.dispose();
			}
		}
		groupToItemsMap.clear();
	}

	public boolean isEmpty() {
		return groupToItemsMap.isEmpty();
	}

	/**
	 * Returns a component to be used as a toolbar.
	 * @return the toolbar component.
	 */
	public JComponent getToolBar() {
		// UNUSUAL CODE ALERT
		// We are trying to make this method thread safe without using synchronization.
		// Synchronizing the method results in possible deadlock with Swing's treeLock
		JComponent localToolBar = toolBar;
		if (localToolBar == null) {
			localToolBar = buildToolbar();
			toolBar = localToolBar;
		}
		return localToolBar;
	}

	private JComponent buildToolbar() {
		JComponent newToolBar = new VariableHeightPanel(true, 0, 0);
		newToolBar.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));

		boolean isFirstGroup = true;
		Set<Entry<String, List<ToolBarItemManager>>> entrySet = groupToItemsMap.entrySet();
		for (Entry<String, List<ToolBarItemManager>> entry : entrySet) {
			List<ToolBarItemManager> items = entry.getValue();
			if (items.isEmpty()) {
				continue;
			}
			if (!isFirstGroup) {
				insertSeparator(newToolBar);
			}

			addButtonsToToolBar(newToolBar, items);

			isFirstGroup = false;
		}
		return newToolBar;
	}

	private void addButtonsToToolBar(JComponent toolBarComponent, List<ToolBarItemManager> items) {
		Iterator<ToolBarItemManager> iterator = items.iterator();
		while (iterator.hasNext()) {
			ToolBarItemManager item = iterator.next();
			JButton button = item.getButton();
			toolBarComponent.add(button);
		}
	}

	private void insertSeparator(JComponent toolBarComponent) {
		toolBarComponent.add(Box.createHorizontalStrut(5));  // add space before separator                      
		toolBarComponent.add(DockingUtils.createToolbarSeparator());
		toolBarComponent.add(Box.createHorizontalStrut(5));  // add space after separator
	}

	/**
	 * Removes the action from the toolbar.
	 * @param action the action to be removed.
	 */
	public void removeAction(DockingActionIf action) {
		ToolBarData toolBarData = action.getToolBarData();
		if (toolBarData == null) {
			return;
		}

		String group = toolBarData.getToolBarGroup();
		List<ToolBarItemManager> groupItems = groupToItemsMap.get(group);
		if (groupItems == null) {
			return; // must have been cleared already
		}
		Iterator<ToolBarItemManager> it = groupItems.iterator();
		while (it.hasNext()) {
			ToolBarItemManager item = it.next();
			if (item.getAction() == action) {
				item.dispose();
				it.remove();
				toolBar = null; // trigger a rebuild of the menu
			}
		}

		if (groupItems.isEmpty()) {
			groupToItemsMap.remove(group); // no actions left
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class GroupComparator implements Comparator<String> {

		@Override
		public int compare(String group1, String group2) {
			if (group1 == null && group2 == null) {
				return 0;
			}
			if (group1 == null) {
				return 1;
			}
			if (group2 == null) {
				return -1;
			}
			return group1.compareTo(group2);
		}
	}

	private class ToolBarItemManagerComparator implements Comparator<ToolBarItemManager> {

		@Override
		public int compare(ToolBarItemManager t1, ToolBarItemManager t2) {
			DockingActionIf action1 = t1.getAction();
			DockingActionIf action2 = t2.getAction();
			ToolBarData toolBarData1 = action1.getToolBarData();
			ToolBarData toolBarData2 = action2.getToolBarData();
			String subGroup1 = toolBarData1.getToolBarSubGroup();
			String subGroup2 = toolBarData2.getToolBarSubGroup();

			int result = subGroup1.compareTo(subGroup2);
			if (result != 0) {
				return result;
			}

			// when the group is the same, sort by the owner (this results in 
			// insertion-based sorting for actions that come from the same owner)
			String name1 = action1.getOwner();
			String name2 = action2.getOwner();
			return name1.compareTo(name2);
		}

	}
}
