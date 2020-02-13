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

import java.util.*;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.actions.DeleteTableRowAction;

/**
 * Plugin to show a list of references to the item represented by the location of the cursor.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays references to a location",
	description = "This plugin provides a component to show a list of references to the current item under the cursor.",
	servicesRequired = { ProgramManager.class, GoToService.class },
	servicesProvided = { FindAppliedDataTypesService.class, LocationReferencesService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class LocationReferencesPlugin extends Plugin
		implements FindAppliedDataTypesService, LocationReferencesService {

	protected static final String SEARCH_OPTION_NAME = "Search";
	protected static final String DATA_TYPE_DISCOVERY_OPTION_NAME = "Dynamic Data Type Discovery";

	private DockingAction referencesToAction;
	private DockingAction referencesToAddressAction;
	private List<LocationReferencesProvider> providerList = new ArrayList<>();
	private LocationReferencesProvider lastHiddenProvider;
	private HelpLocation helpLocation;

	public LocationReferencesPlugin(PluginTool tool) {
		super(tool);

		helpLocation = new HelpLocation(this.getName(), "Location_References_Plugin");
		createActions();
	}

	@Override
	protected void init() {
		initOptions();
		LocationReferencesHighlighter.registerHighlighterOptions(this);
	}

	private void initOptions() {
		ToolOptions options = tool.getOptions(SEARCH_OPTION_NAME);
		options.registerOption(DATA_TYPE_DISCOVERY_OPTION_NAME, true,
			new HelpLocation("LocationReferencesPlugin", "Data_Type_Discovery"),
			"True signals that Data Type searches should use data type discovery " +
				"for types that are not applied in the Listing.  This option will " +
				"slow the search.");
	}

	private void createActions() {
		int subGroupPosition = 0;
		referencesToAction = new FindReferencesToAction(this, subGroupPosition);
		referencesToAction.setHelpLocation(helpLocation);
		tool.addAction(referencesToAction);

		subGroupPosition++;
		referencesToAddressAction = new FindReferencesToAddressAction(this, subGroupPosition);
		tool.addAction(referencesToAddressAction);

		//
		// Unusual Code: This plugin does not use the delete action directly, but our transient 
		//               tables do. We need a way to have keybindings shared for this action.  
		//               Further, we need to register it now, not when the transient
		//               providers are created, as they would only appear in the options at 
		//               that point.
		//
		DeleteTableRowAction.registerDummy(tool, getName());
	}

	void displayProvider(ListingActionContext context) {
		if (context.getLocation() == null) {
			return;
		}

		displayProviderForLocation(context.getLocation(), context.getNavigatable());
	}

	boolean useDynamicDataTypeSearching() {

		ToolOptions options = tool.getOptions(LocationReferencesPlugin.SEARCH_OPTION_NAME);
		boolean optionValue =
			options.getBoolean(LocationReferencesPlugin.DATA_TYPE_DISCOVERY_OPTION_NAME, true);
		return optionValue;
	}

	private void displayProviderForLocation(ProgramLocation location, Navigatable navigatable) {
		LocationDescriptor locationDescriptor = getLocationDescriptor(location);
		if (locationDescriptor == null) {
			throw new IllegalArgumentException(
				"Unable to display provider - unknown location: " + location);
		}

		LocationReferencesProvider provider = findProvider(locationDescriptor, navigatable);
		if (provider == null) {
			provider = new LocationReferencesProvider(this, locationDescriptor, navigatable);
		}
		else {
			// just refresh the existing provider
			updateProvider(provider, locationDescriptor);
		}

		tool.showComponentProvider(provider, true);

// REFS: is the following statement true???...it seems that the loading is off the swing thread, 
// so it still may not be done at this point!

		// we add the provider here instead of where it is created above to allow the provider to
		// be initialized before this plugin can reference it in its list (this prevents
		// multithreaded access from using the provider before it has been initialized).
		if (!providerList.contains(provider)) {
			providerList.add(provider);
		}
	}

	private LocationReferencesProvider findProvider(LocationDescriptor newLocationDescriptor,
			Navigatable navigatable) {
		// start backward to get the most recently added provider first
		for (int i = providerList.size() - 1; i >= 0; i--) {
			LocationReferencesProvider provider = providerList.get(i);
			LocationDescriptor descriptor = provider.getLocationDescriptor();
			if (descriptor.equals(newLocationDescriptor)) {
				Navigatable providerNavigatable = provider.getNavigatable();
				if (providerNavigatable.equals(navigatable)) {
					return provider;
				}
			}
		}
		return null;
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	public void dispose() {
		tool.removeAction(referencesToAction);
		referencesToAction.dispose();
		disposeProviderList();
		super.dispose();
	}

	private void disposeProviderList() {
		for (int i = 0; i < providerList.size(); i++) {
			LocationReferencesProvider provider = providerList.get(i);
			provider.dispose();
		}
		providerList.clear();
	}

	private void updateProvider(LocationReferencesProvider provider,
			LocationDescriptor locationDescriptor) {
		provider.update(locationDescriptor);
	}

	LocationDescriptor getLocationDescriptor(ProgramLocation programLocation) {
		return ReferenceUtils.getLocationDescriptor(programLocation);
	}

	void providerDismissed(LocationReferencesProvider provider) {
		providerList.remove(provider);

		if (provider == lastHiddenProvider) {
			lastHiddenProvider = null;
		}

		provider.dispose();
	}

	// Used to let the plugin know the last provider that was hidden.  The plugin uses this
	// info to signal that this provider should perform local cleanup in the event that another
	// provider is shown.
	void providerDeactivated(LocationReferencesProvider provider) {
		lastHiddenProvider = provider;
	}

	void providerActivated(LocationReferencesProvider provider) {
		// cleanup old highlight data if it exists and we are not the previous provider
		if ((lastHiddenProvider != null) && !lastHiddenProvider.equals(provider)) {
			lastHiddenProvider.clearHighlights();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programClosed(program);
			return;
		}
	}

	protected void programClosed(Program program) {
		for (Iterator<LocationReferencesProvider> iterator =
			providerList.iterator(); iterator.hasNext();) {
			LocationReferencesProvider provider = iterator.next();
			if (provider.getProgram() == program) {
				provider.dispose();
				iterator.remove();
			}
		}
	}

	private void showProvider(Program program, LocationReferencesProvider provider,
			LocationDescriptor locationDescriptor, Navigatable navigatable) {

		if (provider == null) {
			provider = new LocationReferencesProvider(this, locationDescriptor, navigatable);
		}
		else {
			// just refresh the existing provider
			updateProvider(provider, locationDescriptor);
		}
		tool.showComponentProvider(provider, true);

		// we add the provider here instead of where it is created above to allow the provider to
		// be initialized before this plugin can reference it in its list (this prevents
		// multithreaded access from using the provider before it has been initialized).
		if (!providerList.contains(provider)) {
			providerList.add(provider);
		}
	}

	@Override
	public void findAndDisplayAppliedDataTypeAddresses(DataType dataType) {
		ProgramManager programManagerService = tool.getService(ProgramManager.class);
		GoToService goToService = tool.getService(GoToService.class);
		Program program = programManagerService.getCurrentProgram();
		if (program == null) {
			Msg.showInfo(this, null, "Find References To...",
				"You must have a program open in order to use the 'Find References To...' action");
			return; // cannot find references to a data type if there is no open program
		}

		ProgramLocation genericLocation = new GenericDataTypeProgramLocation(program, dataType);
		LocationDescriptor locationDescriptor = getLocationDescriptor(genericLocation);
		Navigatable navigatable = goToService.getDefaultNavigatable();
		LocationReferencesProvider provider = findProvider(locationDescriptor, navigatable);
		showProvider(program, provider, locationDescriptor, navigatable);
	}

	@Override
	public void findAndDisplayAppliedDataTypeAddresses(Composite dataType, String fieldName) {
		ProgramManager programManagerService = tool.getService(ProgramManager.class);
		GoToService goToService = tool.getService(GoToService.class);
		Program program = programManagerService.getCurrentProgram();
		if (program == null) {
			Msg.showInfo(this, null, "Find References To...",
				"You must have a program open in order to use the 'Find References To...' action");
			return; // cannot find references to a data type if there is no open program
		}

		ProgramLocation genericLocation =
			new GenericCompositeDataTypeProgramLocation(program, dataType, fieldName);
		LocationDescriptor locationDescriptor = getLocationDescriptor(genericLocation);
		Navigatable navigatable = goToService.getDefaultNavigatable();
		LocationReferencesProvider provider = findProvider(locationDescriptor, navigatable);
		showProvider(program, provider, locationDescriptor, navigatable);
	}

	@Override
	public void showReferencesToLocation(ProgramLocation location, Navigatable navigatable) {
		if (location == null) {
			throw new NullPointerException("Cannot show references to a null location");
		}
		displayProviderForLocation(location, navigatable);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	void fireContextChanged(LocationReferencesProvider provider) {
		tool.contextChanged(provider);
	}
}
