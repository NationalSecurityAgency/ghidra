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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.EditListener;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tabbedpane.DockingTabRenderer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * Panel that has a tabbed pane to switch between the views.
 */
class ViewPanel extends JPanel implements ChangeListener {

	private JTabbedPane tabbedPane;
	private ViewManagerComponentProvider provider;
	private HashMap<String, ViewProviderService> map;
	private DockingAction closeAction;
	private DockingAction deleteAction;
	private DockingAction renameAction;
	private DockingAction[] localActions;
	private PluginTool tool;

	ViewPanel(PluginTool tool, ViewManagerComponentProvider provider) {
		this.provider = provider;
		this.tool = tool;

		map = new HashMap<>();
		create();
		createActions();
	}

	public boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * Add a view component to the tabbed pane and make this view active; set
	 * other views to be inactive.
	 * 
	 * @param vp view provider
	 */
	void addView(ViewProviderService vp) {

		if (!provider.isInTool()) {
			provider.addToTool();
		}

		String name = vp.getViewName();
		if (map.remove(name) != null) {
			map.put(name, vp);
			setCurrentView(name);
		}
		else {
			// remove us as a listener so that the view change does not
			// go out as a result of just adding a view provider
			tabbedPane.removeChangeListener(this);
			try {
				int index = tabbedPane.indexOfTab(name);
				if (index >= 0) {
					tabbedPane.remove(index);
				}
				map.put(name, vp);
				int insertIndex = tabbedPane.getTabCount();
				final JComponent viewComponent = vp.getViewComponent();
				tabbedPane.insertTab(name, null, viewComponent, null, insertIndex);
				tabbedPane.setTabComponentAt(insertIndex, new DockingTabRenderer(tabbedPane, name,
					name, e -> closeView(getViewProviderForComponent(viewComponent), true)));
			}
			finally {
				tabbedPane.addChangeListener(this);
			}
		}
	}

	boolean removeView(ViewProviderService vps) {
		String viewName = vps.getViewName();
		tabbedPane.removeChangeListener(this);
		// remove us as a listener so that the viewChanged() method is
		// not called while we are removing the view provider
		try {
			int index = tabbedPane.indexOfTab(viewName);
			if (index < 0) {
				throw new AssertException(
					"Tabbed Pane does not contain " + viewName + ", but was in the view map!");
			}
			boolean tabSelected = (index == tabbedPane.getSelectedIndex());
			tabbedPane.remove(index);
			map.remove(viewName);
			if (tabSelected) {
				viewChanged();
			}
		}
		finally {
			tabbedPane.addChangeListener(this);
		}

		/*if (isEmpty()) {
			provider.removeFromTool();
		}*/

		return true;
	}

	AddressSetView getCurrentView() {
		ViewProviderService v = getCurrentViewProvider();
		if (v != null) {
			return v.getCurrentView();
		}
		return null;
	}

	boolean isTabClick(MouseEvent event) {
		Component component = event.getComponent();
		int tabCount = tabbedPane.getTabCount();
		for (int i = 0; i < tabCount; i++) {
			DockingTabRenderer renderer = (DockingTabRenderer) tabbedPane.getTabComponentAt(i);
			if (SwingUtilities.isDescendingFrom(component, renderer)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Set the current view to be the component with the given name.
	 * 
	 * @param viewName name of view to be current
	 * @return true if the viewName was found in the provider map
	 */
	boolean setCurrentView(String viewName) {

		ViewProviderService v = map.get(viewName);
		if (v == null) {
			return false;
		}

		JComponent c = v.getViewComponent();
		if (tabbedPane.getSelectedComponent() == c) {
			viewChanged();
		}

		int index = tabbedPane.indexOfComponent(c);
		if (index == -1) {
			// odd case where creating/deleting program trees and then rapidly performing
			// undo/redo operations can lead to a stack trace.
			return true;
		}

		tabbedPane.setSelectedComponent(c); // causes a state change event

		updateLocalActions(v);
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {

			String key = iter.next();
			ViewProviderService vps = map.get(key);
			JComponent comp = vps.getViewComponent();
			if (c != comp) {
				vps.setHasFocus(false);
			}
		}
		return true;
	}

	String getCurrentViewName() {
		ViewProviderService v = getCurrentViewProvider();
		if (v != null) {
			return v.getViewName();
		}
		return null;
	}

	/**
	 * Add the location to the selection in the view.
	 * 
	 * @param loc location to add
	 * 
	 * @return ViewMap new view map
	 */
	AddressSetView addToView(ProgramLocation loc) {
		ViewProviderService v = getCurrentViewProvider();
		if (v != null) {
			return v.addToView(loc);
		}
		return null;
	}

	/**
	 * Get the current view provider.
	 * 
	 * @return ViewProviderService null if there is no view provider.
	 */
	ViewProviderService getCurrentViewProvider() {
		Component c = tabbedPane.getSelectedComponent();
		return getViewProviderForComponent(c);
	}

	ViewProviderService getViewProviderForComponent(Component component) {
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String name = iter.next();
			ViewProviderService v = map.get(name);
			if (v.getViewComponent() == component) {
				return v;
			}
		}
		return null;
	}

	int getNumberOfViews() {
		return map.size();
	}

	/**
	 * Remove all views in the tabbed pane.
	 */
	void dispose() {
		tabbedPane.removeAll();
	}

	void viewNameChanged(ViewProviderService vps, String oldName) {
		ViewProviderService s = map.remove(oldName);
		if (s == null) {
			return; // already updated
		}

		String viewName = vps.getViewName();
		map.put(viewName, vps);

		for (int i = 0; i < map.size(); i++) {
			Component c = tabbedPane.getComponentAt(i);
			if (c == vps.getViewComponent()) {
				DockingTabRenderer renderer = (DockingTabRenderer) tabbedPane.getTabComponentAt(i);
				renderer.setTitle(viewName, viewName);
				break;
			}
		}
	}

	/**
	 * Invoked when the target of the listener has changed its state. In this
	 * case, the method is called when the user switches to another tab in the
	 * tabbed pane.
	 *
	 * @param e the event
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		viewChanged();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	/**
	 * Create actions for popup menu.
	 */
	private void createActions() {

		String owner = provider.getOwner();
		closeAction = new DockingAction("Close Tree View", owner) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				closeView(getCurrentViewProvider(), true);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context.getContextObject() instanceof ViewPanel;
			}
		};
		closeAction.setEnabled(true);

		closeAction.setPopupMenuData(new MenuData(new String[] { "Close" }, null, "TreeView"));

		deleteAction = new DockingAction("Delete Tree View", owner) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				deleteView();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context.getContextObject() instanceof ViewPanel;
			}
		};
		deleteAction.setEnabled(true);

		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, null, "TreeView"));

		renameAction = new DockingAction("Rename Tree View", owner) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				renameView();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return context.getContextObject() instanceof ViewPanel;
			}
		};
		renameAction.setEnabled(true);

		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename" }, null, "TreeView"));

		tool.addAction(closeAction);
		tool.addAction(deleteAction);
		tool.addAction(renameAction);
	}

	/**
	 * Create the tabbed pane.
	 */
	private void create() {
		tabbedPane = new JTabbedPane(SwingConstants.BOTTOM, JTabbedPane.SCROLL_TAB_LAYOUT);

		tabbedPane.addChangeListener(this);
		setLayout(new BorderLayout());

		add(tabbedPane, BorderLayout.CENTER);
		setPreferredSize(new Dimension(200, 300));
	}

	/**
	 * If the panel is active, then set the current view to be active and all
	 * others to be inactive.
	 */
	private void viewChanged() {
		JComponent c = (JComponent) tabbedPane.getSelectedComponent();
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {

			String key = iter.next();
			ViewProviderService v = map.get(key);
			if (c == v.getViewComponent()) {
				v.setHasFocus(true);
				provider.viewChanged(v.getCurrentView());
				updateLocalActions(v);
			}
			else {
				v.setHasFocus(false);
			}
		}
		if (c == null) {
			updateLocalActions(null);
		}
	}

	private void updateLocalActions(ViewProviderService view) {
		if (localActions != null) {
			for (DockingAction localAction : localActions) {
				tool.removeLocalAction(provider, localAction);
			}
			localActions = null;
		}

		if (view != null) {
			localActions = view.getToolBarActions();

			if (localActions != null) {
				for (DockingAction localAction : localActions) {
					tool.addLocalAction(provider, localAction);
				}
			}
		}
	}

	/**
	 * Close the current view.
	 */
	private void closeView(ViewProviderService vps, boolean doNotify) {
		if (vps == null) {
			return;
		}
		if (doNotify) {
			if (!vps.viewClosed()) {
				return;
			}
		}
		String viewName = vps.getViewName();
		ViewProviderService v = map.remove(viewName);
		if (vps == v) {

			int index = tabbedPane.indexOfTab(viewName);
			if (index >= 0) {
				tabbedPane.remove(index);
			}
		}
		else if (v != null) {
			// another service was added with the same name as a
			// result of deleting the view, so put the added one back in
			map.put(viewName, v);
		}

		if (isEmpty()) {
			provider.removeFromTool();
		}
		else {
			// not sure why we are doing this
			if (tabbedPane.getSelectedIndex() != 0) {
				tabbedPane.setSelectedIndex(0);
			}
		}
		viewChanged();
		tool.setConfigChanged(true);
	}

	/**
	 * Delete the view and notify the view provider that it is now deleted.
	 */
	private void deleteView() {
		ViewProviderService vps = getCurrentViewProvider();
		if (vps != null) {
			if (vps.viewDeleted()) {
				closeView(vps, false);
			}
		}
	}

	/**
	 * Pop up editor window to allow the user to rename view.
	 */
	private void renameView() {
		ViewProviderService vps = getCurrentViewProvider();
		int tabIndex = tabbedPane.getSelectedIndex();
		String oldName = vps.getViewName();
		Rectangle rect = tabbedPane.getBoundsAt(tabIndex);
		tool.showEditWindow(oldName, tabbedPane, rect, new RenameListener(vps, tabIndex));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class RenameListener implements EditListener {

		private ViewProviderService vps;
		private int tabIndex;

		RenameListener(ViewProviderService vps, int tabIndex) {
			this.vps = vps;
			this.tabIndex = tabIndex;
		}

		@Override
		public void editCompleted(String newName) {

			if (newName.length() == 0) {

				Msg.showError(getClass(), null, "Invalid Name", "Please enter a valid name.");

				String oldName = vps.getViewName();
				Rectangle rect = tabbedPane.getBoundsAt(tabIndex);
				tool.showEditWindow(oldName, tabbedPane, rect, this);
				return;
			}

			String oldName = vps.getViewName();
			if (!newName.equals(oldName)) {
				if (vps.viewRenamed(newName)) {
					int selectedIndex = tabbedPane.getSelectedIndex();
					tabbedPane.setTitleAt(selectedIndex, newName);
					DockingTabRenderer renderer =
						(DockingTabRenderer) tabbedPane.getTabComponentAt(selectedIndex);
					renderer.setTitle(newName, newName);
					map.remove(oldName);
					map.put(newName, vps);
				}
			}

		}
	}

}
