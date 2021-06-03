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
package ghidra.app.plugin.core.table;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import docking.ActionContext;
import docking.ComponentProviderActivationListener;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import resources.ResourceManager;

public class TableComponentProvider<T> extends ComponentProviderAdapter
		implements TableModelListener, NavigatableRemovalListener {

	private JPanel componentPanel;
	private GhidraThreadedTablePanel<T> threadedPanel;
	private GhidraTableFilterPanel<T> tableFilterPanel;
	private TableServicePlugin tableServicePlugin;
	private Program program;
	private GhidraProgramTableModel<T> model;
	private MarkerSet markerSet;
	private MarkerService markerService;
	private String programName;
	private String windowSubMenu;
	private List<ComponentProviderActivationListener> activationListenerList = new ArrayList<>();

	private Navigatable navigatable;
	private SelectionNavigationAction selectionNavigationAction;
	private DockingAction selectAction;
	private DockingAction removeItemsAction;

	private HelpLocation helpLoc = new HelpLocation(HelpTopics.SEARCH, "Query_Results");

	TableComponentProvider(TableServicePlugin plugin, String title, String name,
			GhidraProgramTableModel<T> model, String programName, GoToService gotoService,
			String windowSubMenu, Navigatable navigatable) {
		this(plugin, title, name, model, programName, gotoService, null, null, null, windowSubMenu,
			navigatable);
	}

	TableComponentProvider(TableServicePlugin plugin, String title, String name,
			GhidraProgramTableModel<T> model, String programName, GoToService gotoService,
			MarkerService markerService, Color markerColor, ImageIcon markerIcon,
			String windowSubMenu, Navigatable navigatable) {
		super(plugin.getTool(), name, plugin.getName());

		this.tableServicePlugin = plugin;
		this.navigatable = navigatable;
		this.program = navigatable.getProgram();
		this.model = model;
		this.programName = programName;
		this.markerService = markerService;
		this.windowSubMenu = windowSubMenu;
		setIcon(ResourceManager.loadImage("images/magnifier.png"));
		setTransient();
		setTitle(title);
		setHelpLocation(helpLoc);

		componentPanel = buildMainPanel(model, gotoService);
		addToTool();
		setVisible(true);
		updateTitle();

		createActions(plugin);

		if (markerService != null) {
			markerSet = markerService.createPointMarker(name, title, program,
				MarkerService.SEARCH_PRIORITY, true, true, false, markerColor, markerIcon);
			markerSet.setMarkerDescriptor(new MarkerDescriptor() {
				@Override
				public ProgramLocation getProgramLocation(MarkerLocation loc) {
					return new BytesFieldLocation(program, loc.getAddr());
				}
			});

			// remove it; we will add it later to a group
			markerService.removeMarker(markerSet, program);
			loadMarkers();
			model.addTableModelListener(this);
		}
	}

	private JPanel buildMainPanel(GhidraProgramTableModel<T> tableModel, GoToService gotoService) {
		JPanel panel = new JPanel(new BorderLayout());

		threadedPanel = new GhidraThreadedTablePanel<>(tableModel);
		GhidraTable table = threadedPanel.getTable();
		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			tool.contextChanged(TableComponentProvider.this);
		});

		// only allow global actions through if we are derived from the connect/primary navigatable
		table.setActionsEnabled(navigatable.isConnected());

		if (gotoService != null) {
			if (navigatable != null) {
				navigatable.addNavigatableListener(this);
			}
			table.installNavigation(gotoService, navigatable);
		}

		panel.add(threadedPanel, BorderLayout.CENTER);
		panel.add(createFilterFieldPanel(table, tableModel), BorderLayout.SOUTH);

		return panel;
	}

	private void createActions(final Plugin plugin) {

		GhidraTable table = threadedPanel.getTable();
		selectAction = new MakeProgramSelectionAction(tableServicePlugin, table) {
			@Override
			protected ProgramSelection makeSelection(ActionContext context) {
				ProgramSelection selection = table.getProgramSelection();
				navigatable.goTo(program, new ProgramLocation(program, selection.getMinAddress()));
				navigatable.setSelection(selection);
				navigatable.requestFocus();
				return selection;
			}
		};
		selectAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Make_Selection"));

		selectionNavigationAction = new SelectionNavigationAction(plugin, table);
		selectionNavigationAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, "Selection_Navigation"));

		DockingAction externalGotoAction = new DockingAction("Go to External Location", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				gotoExternalAddress(getSelectedExternalAddress());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return getSelectedExternalAddress() != null &&
					tool.getService(GoToService.class) != null;
			}

			private Address getSelectedExternalAddress() {
				if (table.getSelectedRowCount() != 1) {
					return null;
				}
				ProgramSelection selection = table.getProgramSelection();
				Program modelProgram = model.getProgram();
				if (modelProgram == null || selection.getNumAddresses() != 1) {
					return null;
				}
				Address addr = selection.getMinAddress();
				return addr.isExternalAddress() ? addr : null;
			}
		};
		externalGotoAction.setDescription("Go to an external location");
		externalGotoAction.setEnabled(false);

		Icon icon = ResourceManager.loadImage("images/searchm_obj.gif");
		externalGotoAction.setPopupMenuData(
			new MenuData(new String[] { "GoTo External Location" }, icon, null));
		externalGotoAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Navigation"));

		plugin.getTool().addLocalAction(this, selectAction);
		plugin.getTool().addLocalAction(this, selectionNavigationAction);
		plugin.getTool().addLocalAction(this, externalGotoAction);
	}

	public void installRemoveItemsAction() {
		if (removeItemsAction != null) {
			return;
		}

		GhidraTable table = threadedPanel.getTable();
		removeItemsAction = new DeleteTableRowAction(table, tableServicePlugin.getName());

		tool.addLocalAction(this, removeItemsAction);
	}

	private JPanel createFilterFieldPanel(JTable table, AbstractSortedTableModel<T> sortedModel) {
		tableFilterPanel = new GhidraTableFilterPanel<>(table, sortedModel);
		tableFilterPanel.setToolTipText("Filter search results");
		return tableFilterPanel;
	}

	private String generateSubTitle() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("(");
		buffer.append(programName);
		buffer.append(") ");
		int n = model.getRowCount();
		if (n == 1) {
			buffer.append("    (1 entry)");
		}
		else if (n > 1) {
			buffer.append("    (" + n + " entries)");
		}
		return buffer.toString();
	}

	private void loadMarkers() {
		if (markerSet == null) {
			return;
		}

		markerSet.clearAll();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {
			ProgramLocation loc = model.getProgramLocation(i, 0);
			if (loc != null) {
				markerSet.add(loc.getByteAddress());
			}
		}

		markerService.setMarkerForGroup(MarkerService.HIGHLIGHT_GROUP, markerSet, program);
	}

	private void gotoExternalAddress(Address extAddr) {
		GoToService gotoSvc = tool.getService(GoToService.class);
		if (gotoSvc != null) {
			gotoSvc.goTo(extAddr, model.getProgram());
		}
	}

	@Override
	public void closeComponent() {
		if (navigatable != null) {
			navigatable.removeNavigatableListener(this);
		}
		tool.removeComponentProvider(this);
		tableServicePlugin.remove(this);
		model.dispose();
		if (markerSet != null) {
			markerSet.clearAll();
			markerService.removeMarker(markerSet, program);
		}
		tableServicePlugin = null;

		threadedPanel.dispose();
		tableFilterPanel.dispose();
	}

	public GThreadedTablePanel<T> getThreadedTablePanel() {
		return threadedPanel;
	}

	@Override
	public JComponent getComponent() {
		return componentPanel;
	}

	public void refresh() {
		GTable threadedTable = threadedPanel.getTable();

		int rowCount = threadedTable.getRowCount(); // must happen before model.refresh()
		if (rowCount == 0) {
			return;
		}

		boolean wasEnabled = selectionNavigationAction.isEnabled();
		selectionNavigationAction.setEnabled(false); // disable navigation events from updates

		int[] selectedRows = threadedTable.getSelectedRows();

		model.refresh(); // current selection is cleared by this call

		restoreSelection(threadedTable, selectedRows);

		// re-enable navigation events after update
		selectionNavigationAction.setEnabled(wasEnabled);
	}

	private void restoreSelection(GTable threadedTable, int[] selectedRows) {
		if (selectedRows.length == 0) {
			return;
		}
		int start = selectedRows[0];
		int end = selectedRows[0];
		for (int row : selectedRows) {
			if (row > end + 1) { // is there a gap?
				threadedTable.addRowSelectionInterval(start, end);
				start = row;
			}
			end = row;
		}
		threadedTable.addRowSelectionInterval(start, end);
	}

	@Override
	public void tableChanged(TableModelEvent ev) {
		updateTitle();
		loadMarkers();
	}

	public GhidraProgramTableModel<T> getModel() {
		return model;
	}

	private void updateTitle() {
		setSubTitle(generateSubTitle());
	}

	public void addActivationListener(ComponentProviderActivationListener listener) {
		activationListenerList.add(listener);
	}

	public void removeActivationListener(ComponentProviderActivationListener listener) {
		activationListenerList.remove(listener);
	}

	/**
	 * @see docking.ComponentProvider#componentActivated()
	 */
	@Override
	public void componentActivated() {
		loadMarkers();
		for (ComponentProviderActivationListener listener : activationListenerList) {
			listener.componentProviderActivated(this);
		}
	}

	/**
	 * @see docking.ComponentProvider#componentDeactived()
	 */
	@Override
	public void componentDeactived() {
		for (ComponentProviderActivationListener listener : activationListenerList) {
			listener.componentProviderDeactivated(this);
		}
	}

	/**
	 * @see docking.ComponentProvider#getWindowSubMenuName()
	 */
	@Override
	public String getWindowSubMenuName() {
		return windowSubMenu;
	}

	@Override
	public void navigatableRemoved(Navigatable removedNavigatable) {
		removedNavigatable.removeNavigatableListener(this);
		closeComponent();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, threadedPanel.getTable());
	}

}
