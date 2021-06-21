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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.Collection;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.table.GTable;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

/**
 * ComponentProvider for the {@link LocationReferencesPlugin}.
 */
public class LocationReferencesProvider extends ComponentProviderAdapter
		implements DomainObjectListener, NavigatableRemovalListener {

	private static Icon HIGHLIGHT_ICON = ResourceManager.loadImage("images/tag_yellow.png");
	private static Icon HOME_ICON = ResourceManager.loadImage("images/go-home.png");
	private static Icon REFRESH_ICON = Icons.REFRESH_ICON;
	private static Icon REFRESH_NOT_NEEDED_ICON =
		ResourceManager.getDisabledIcon(Icons.REFRESH_ICON, 60);

	private static final String TITLE_PREFIX_REFERENCES = "References to ";
	private static final String TITLE_PREFIX_USAGE = "Uses of ";

	public static final String NAME = "Location References Provider";

	private LocationReferencesPlugin locationReferencesPlugin;
	private LocationReferencesHighlighter highlightManager;
	private LocationReferencesPanel referencesPanel;

	private JComponent providerComponent;
	private DockingAction homeAction;
	private DockingAction selectionAction;
	private ToggleDockingAction highlightAction;
	private DockingAction refreshAction;

	private AddressSet addressSetCache;

	private SwingUpdateManager updateManager;
	private LocationDescriptor currentLocationDescriptor;

	// listens for when the data may have become stale
	private ChangeListener modelFreshnessListener =
		e -> refreshAction.getToolBarData().setIcon(REFRESH_ICON);
	private final Navigatable navigatable;
	private Program program;

	LocationReferencesProvider(LocationReferencesPlugin locationReferencesPlugin,
			LocationDescriptor locationDescriptor, Navigatable navigatable) {
		super(locationReferencesPlugin.getTool(), NAME, locationReferencesPlugin.getName());
		this.locationReferencesPlugin = locationReferencesPlugin;
		this.currentLocationDescriptor = locationDescriptor;
		this.navigatable = navigatable;

		this.program = navigatable.getProgram();
		navigatable.addNavigatableListener(this);
		program.addListener(this);

		setTitle(TITLE_PREFIX_REFERENCES);
		setHelpLocation(
			new HelpLocation(locationReferencesPlugin.getName(), "LocationReferencesPlugin"));
		setWindowMenuGroup("References");
		setTransient();
		createView();
		addToTool();
		createActions();
		addListeners();

		updateManager = new SwingUpdateManager(1000, 10000, () -> {
			Icon refreshIcon = refreshAction.getToolBarData().getIcon();
			boolean refresh = (refreshIcon == REFRESH_ICON);
			if (refresh) {
				doUpdateAndReloadReferencesTable();
				refreshAction.getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
			}
			else {
				doUpdateReferencesTable();
			}

		});

		// this initializes our GUI components properly, now that they have been created
		setLocationDescriptor(locationDescriptor, navigatable);

		referencesPanel.getTable().getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			locationReferencesPlugin.fireContextChanged(LocationReferencesProvider.this);
		});

		setVisible(true);
	}

	/**
	 * @see DomainObjectListener#domainObjectChanged(DomainObjectChangedEvent)
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent changeEvent) {
		currentLocationDescriptor.domainObjectChanged(changeEvent);
	}

	@Override
	public void navigatableRemoved(Navigatable theNavigatable) {
		locationReferencesPlugin.providerDismissed(this);
	}

	private void doUpdateReferencesTable() {
		referencesPanel.updateModel();
	}

	private void doUpdateAndReloadReferencesTable() {
		referencesPanel.reloadModel();
	}

	private void setLocationDescriptor(LocationDescriptor locationDescriptor,
			Navigatable navigatable) {
		// turn off highlighting, as we have a new descriptor, which may change the data
		if (highlightManager != null) {
			highlightManager.dispose();
		}
		highlightManager =
			new LocationReferencesHighlighter(locationReferencesPlugin, this, navigatable);
		clearHighlights();

		currentLocationDescriptor = locationDescriptor;
		currentLocationDescriptor.setModelFreshnessListener(modelFreshnessListener);

		updateHomeActionState();

		setTitle(generateTitle());
	}

	/** 
	 * Sets the new LocationDescriptor and updates the providers table contents. 
	 * @param locationDescriptor the new descriptor 
	 */
	void update(LocationDescriptor locationDescriptor) {
		setLocationDescriptor(locationDescriptor, navigatable);
		updateManager.updateNow();
	}

	private void updateHighlights() {
		// if the data is initializing, then this method will be called when it is finished
		if (!referencesPanel.isInitialized()) {
			return;
		}

		// don't change the highlights if we are not providing the highlights
		if (this != highlightManager.getCurrentHighlightProvider()) {
			return;
		}

		highlightManager.setHighlightingEnabled(highlightAction.isSelected());
	}

	void clearHighlights() {
		highlightManager.setHighlightingEnabled(false);
	}

	void dispose() {
		updateManager.dispose();
		referencesPanel.dispose();
		highlightManager.dispose();
		navigatable.removeNavigatableListener(this);
		program.removeListener(this);
		program = null;

		tool.removeComponentProvider(this);

		homeAction.dispose();
		refreshAction.dispose();
		highlightAction.dispose();
		selectionAction.dispose();
	}

	LocationDescriptor getLocationDescriptor() {
		return currentLocationDescriptor;
	}

	boolean useDynamicDataTypeSearching() {
		return locationReferencesPlugin.useDynamicDataTypeSearching();
	}

//==================================================================================================
// Setup methods
//==================================================================================================
	private void createView() {
		providerComponent = new JPanel(new BorderLayout(10, 10));
		providerComponent.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		referencesPanel = new LocationReferencesPanel(this);
		providerComponent.add(referencesPanel, BorderLayout.CENTER);
	}

	private void createActions() {

		homeAction = new DockingAction("Home", locationReferencesPlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				goTo(currentLocationDescriptor.getHomeLocation(),
					currentLocationDescriptor.getProgram());
			}
		};

		homeAction.setToolBarData(new ToolBarData(HOME_ICON));
		updateHomeActionState();

		selectionAction =
			new MakeProgramSelectionAction(locationReferencesPlugin, referencesPanel.getTable());

		highlightAction = new ToggleDockingAction("Highlight Matches", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateHighlights();
			}
		};

		highlightAction.setToolBarData(new ToolBarData(HIGHLIGHT_ICON));
		highlightAction.setSelected(true);
		highlightAction.setDescription("Highlight matches in tool");

		refreshAction = new DockingAction("Refresh", locationReferencesPlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateManager.updateNow();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_NOT_NEEDED_ICON));
		refreshAction.setDescription(
			"<html>Push at any time to refresh the current table of references.<br>" +
				"This button is highlighted when the data <i>may</i> be stale.<br>");

		SelectionNavigationAction selectionNavigationAction =
			new SelectionNavigationAction(locationReferencesPlugin, referencesPanel.getTable());

		GhidraTable table = referencesPanel.getTable();
		DockingAction removeItemsAction = new DeleteAction(tool, table);
		removeItemsAction.setEnabled(false); // off by default; updated when the user clicks the table
		tool.addLocalAction(this, homeAction);
		tool.addLocalAction(this, refreshAction);
		tool.addLocalAction(this, selectionAction);
		tool.addLocalAction(this, highlightAction);
		tool.addLocalAction(this, removeItemsAction);
		tool.addLocalAction(this, selectionNavigationAction);

		setHelpLocation();
	}

	private void updateHomeActionState() {
		// we have no home location sometimes, like when launched from the service interface when
		// looking for references to datatypes
		boolean hasHomeLocation = currentLocationDescriptor.getHomeLocation() != null;
		homeAction.setEnabled(hasHomeLocation);

		String description =
			hasHomeLocation ? "Go back to the location from where this dialog was generated"
					: "No home location";
		homeAction.setDescription(description);
	}

	private void setHelpLocation() {
		homeAction.setHelpLocation(new HelpLocation(locationReferencesPlugin.getName(), "Home"));
		refreshAction.setHelpLocation(
			new HelpLocation(locationReferencesPlugin.getName(), "Refresh"));
		selectionAction.setHelpLocation(
			new HelpLocation(locationReferencesPlugin.getName(), "Select"));
		highlightAction.setHelpLocation(
			new HelpLocation(locationReferencesPlugin.getName(), "Highlight"));
	}

	private void goTo(ProgramLocation loc, Program theProgram) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(loc, theProgram);
	}

	private void addListeners() {
		final JTable table = referencesPanel.getTable();
		table.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				selectionAction.setEnabled(table.getSelectedRowCount() > 0);
			}
		});

		// callback to know when to update our state
		referencesPanel.addTableModelListener(e -> {
			// invalidate our cache
			addressSetCache = null;
			updateHighlights();

			setTitle(generateTitle() + " - " + table.getRowCount() + " locations");
		});
	}

	private String generateTitle() {

		String suffix =
			(currentLocationDescriptor == null) ? "" : currentLocationDescriptor.getLabel();
		if (currentLocationDescriptor instanceof DataTypeLocationDescriptor) {
			return TITLE_PREFIX_USAGE + suffix;
		}

		return TITLE_PREFIX_REFERENCES + suffix;
	}

	AddressSet getReferenceAddresses(Program theProgram) {
		if (addressSetCache == null) {
			addressSetCache = new AddressSet();
			Collection<Address> referenceAddresses = referencesPanel.getReferenceAddresses();
			for (Address address : referenceAddresses) {
				addressSetCache.addRange(address, address);
			}
		}
		return addressSetCache;
	}

	Navigatable getNavigatable() {
		return navigatable;
	}

	Program getProgram() {
		return program;
	}
//==================================================================================================
// Interface methods
//==================================================================================================

	@Override
	public void closeComponent() {
		locationReferencesPlugin.providerDismissed(this);
	}

	@Override
	public void componentHidden() {
		// Not sure if this can even be called outside of the normal disposal action.  Just in
		// case, free-up some of our resources.  Do not call 
		// locationReferencesPlugin.providerDismissed(this); here, as that can trigger a loop
		// back when we are disposing.
		clearHighlights();
		updateManager.dispose();
		referencesPanel.dispose();
	}

	@Override
	public void componentActivated() {
		locationReferencesPlugin.providerActivated(this);
		updateHighlights();
	}

	@Override
	public void componentDeactived() {
		// let the plugin know, which is acting as a broker for all providers, that we are
		// not focused so that it can callback to us to disable highlights if another provider
		// gains focus
		locationReferencesPlugin.providerDeactivated(this);
	}

	@Override
	public JComponent getComponent() {
		return referencesPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, referencesPanel.getTable());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DeleteAction extends DeleteTableRowAction {

		DeleteAction(PluginTool tool, GTable table) {
			super(table, locationReferencesPlugin.getName());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			super.actionPerformed(context);

			// signal that the data in the table does not match the program
			refreshAction.getToolBarData().setIcon(REFRESH_ICON);
		}
	}
}
