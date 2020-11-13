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
package ghidra.util.table;

import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

import javax.swing.Icon;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.DockingWindowManager;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.framework.options.PreferenceState;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * <a id="description"></a>
 * An action used to trigger navigation callback on instances of {@link JTable}.  Users can 
 * toggle this action to control navigation that is based upon selection.
 * <p>
 * Subclasses need to implement {@link #navigate()}, which will be called when a navigation is
 * triggered on the given table by a selection.
 * <p>
 * This class will save the state of the action when the tool is saved.
 */
public abstract class AbstractSelectionNavigationAction extends ToggleDockingAction {

	private static final Icon ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
	private static final String SELECTED_STATE = "SELECTION_NAVIGATION_SELECTED_STATE";

	private SelectionListener selectionListener;
	private boolean isInitialized;
	protected final JTable table;

	protected AbstractSelectionNavigationAction(String name, String owner, JTable table) {
		super(name, owner, false);
		this.table = table;

		selectionListener = new SelectionListener();

		setToolBarData(new ToolBarData(ICON));
		setDescription(HTMLUtilities.toHTML("Toggle <b>on</b> means to navigate to the location\n" +
			"in the program that corresponds to the selected row,\n as the selection changes."));
		setHelpLocation(new HelpLocation("Search", "Selection_Navigation"));
		setEnabled(true);
		setSelected(true); // toggle button; enabled by default

		initialize();
	}

	/**
	 * Users of this class will implement this method to know when to use their table to perform
	 * navigation tasks in their own way.
	 */
	public abstract void navigate();

	@Override
	// overridden to toggle the selection listener when the action is disabled
	public void setEnabled(boolean enable) {
		super.setEnabled(enable);

		boolean installListener = enable && isSelected();
		toggleSelectionListening(installListener);
	}

	@Override
	// overridden to toggle the selection listener when the state changes
	public void setSelected(boolean value) {
		super.setSelected(value);
		toggleSelectionListening(value);
	}

	protected void toggleSelectionListening(boolean listen) {
		if (table == null) {
			return; // called during initialization
		}

		if (listen) {
			table.getSelectionModel().addListSelectionListener(selectionListener);
		}
		else {
			table.getSelectionModel().removeListSelectionListener(selectionListener);
		}

		saveState();
	}

	private class SelectionListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting()) {
				return;
			}

			if (table.getSelectedRowCount() != 1) {
				return;
			}

			navigate();
		}
	}

//==================================================================================================
// Persistence Methods
//==================================================================================================

	private void initialize() {
		// We want to load our state after we have been associated with a DockingWindowManager. 
		// If the table is displayable, then we are are properly setup...
		if (table.isDisplayable()) {
			restoreState();
			return;
		}

		// ...otherwise, we are using this listener to know when the table has been added to 
		// the component hierarchy, as it has been connected to a DockingWindowManager by then.
		table.addHierarchyListener(new HierarchyListener() {
			@Override
			public void hierarchyChanged(HierarchyEvent e) {
				long changeFlags = e.getChangeFlags();
				if (HierarchyEvent.DISPLAYABILITY_CHANGED == (changeFlags &
					HierarchyEvent.DISPLAYABILITY_CHANGED)) {

					// check for the first time we are put together                    
					if (table.isDisplayable()) {
						restoreState();
						table.removeHierarchyListener(this); // cleanup
					}
				}
			}
		});
	}

	protected void saveState() {
		if (!isInitialized) {
			return; // don't save any state changes until we're finished initializing
		}

		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
		if (dockingWindowManager == null) {
			return;
		}

		PreferenceState preferenceState = new PreferenceState();
		preferenceState.putBoolean(SELECTED_STATE, isSelected());

		dockingWindowManager.putPreferenceState(getOwner(), preferenceState);
	}

	protected void restoreState() {
		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
		if (dockingWindowManager == null) {
			return;
		}

		PreferenceState preferenceState = dockingWindowManager.getPreferenceState(getOwner());

		// restore any previously saved settings
		if (preferenceState != null) {
			boolean selectedValue = preferenceState.getBoolean(SELECTED_STATE, true);
			setSelected(selectedValue);
		}

		isInitialized = true;
	}
}
