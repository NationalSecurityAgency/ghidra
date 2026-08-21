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
package datagraph;

import java.util.HashSet;
import java.util.Set;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.AbstractLocationPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Plugin for showing a graph of data from the listing.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Data Graph",
	description = """
		Plugin for displaying graphs of data objects in memory. From any data object in the
		listing, the user can display a graph of that data object. Initially, a graph will be shown
		with one vertex that has a scrollable view of the values in memory associated with that data. 
		Also, any pointers or references from or to that data can be explored by following the
		references and creating additional vertices for the referenced code or data.
	""",
	eventsConsumed = {
		ProgramLocationPluginEvent.class,
	},
	eventsProduced = {
		ProgramLocationPluginEvent.class, 
	}
)
//@formatter:on
public class DataGraphPlugin extends ProgramPlugin {
	private static final String NAVIGATE_IN = "Navigate In";
	private static final String NAVIGATE_OUT = "Navigate Out";
	private static final String COMPACT_FORMAT = "Compact Format";
	private static final String SHOW_POPUPS = "Show Popups";
	private Set<DataGraphProvider> activeProviders = new HashSet<>();
	private DegSharedConfig sharedConfig = new DegSharedConfig();

	public DataGraphPlugin(PluginTool plugintool) {
		super(plugintool);
		createActions();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof AbstractLocationPluginEvent ev) {
			ProgramLocation location = ev.getLocation();
			setLocation(location);
		}
	}

	/**
	 * Pass incoming tool location events to each active provider.
	 * @param location the new tool location
	 */
	public void setLocation(ProgramLocation location) {
		activeProviders.forEach(p -> p.setLocation(location));
	}

	@Override
	public void readConfigState(SaveState saveState) {
		sharedConfig.setNavigateIn(saveState.getBoolean(NAVIGATE_IN, false));
		sharedConfig.setNavigateOut(saveState.getBoolean(NAVIGATE_OUT, true));
		sharedConfig.setCompactFormat(saveState.getBoolean(COMPACT_FORMAT, true));
		sharedConfig.setShowPopups(saveState.getBoolean(SHOW_POPUPS, true));
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putBoolean(NAVIGATE_IN, sharedConfig.isNavigateIn());
		saveState.putBoolean(NAVIGATE_OUT, sharedConfig.isNavigateOut());
		saveState.putBoolean(COMPACT_FORMAT, sharedConfig.useCompactFormat());
		saveState.putBoolean(SHOW_POPUPS, sharedConfig.isShowPopups());
	}

	private void createActions() {

		new ActionBuilder("Display Data Graph", getName())
				.menuPath("&Graph", "Data")
				.menuGroup("Graph", "Data")
				.popupMenuPath("Data", "Display Data Graph")
				.keyBinding("ctrl G")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Data_Graph"))
				.withContext(ListingActionContext.class)
				.enabledWhen(this::isGraphActionEnabled)
				.onAction(this::showDataGraph)
				.buildAndInstall(tool);
	}

	protected boolean isGraphActionEnabled(ListingActionContext context) {
		return context.getCodeUnit() instanceof Data;
	}

	private void showDataGraph(ListingActionContext context) {
		Data data = (Data) context.getCodeUnit();
		// the data from the context may be an internal sub-data, we want the outermost data.
		data = getTopLevelData(data);
		DataGraphProvider provider =
			new DataGraphProvider(this, context.getNavigatable(), data, sharedConfig);
		activeProviders.add(provider);
		tool.showComponentProvider(provider, true);
	}

	private Data getTopLevelData(Data data) {
		Data parent = data.getParent();
		while (parent != null) {
			data = parent;
			parent = data.getParent();
		}
		return data;
	}

	void removeProvider(DataGraphProvider provider) {
		activeProviders.remove(provider);
	}

}
