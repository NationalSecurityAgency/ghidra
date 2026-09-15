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
package functioncalls.plugin;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.task.SwingUpdateManager;

/**
 * Plugin to show a graph of function calls for a given function
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Function Call Graph Plugin",
	description = "Displays a graph of incoming and outgoing calls for a given function."
)
//@formatter:on
public class FunctionCallGraphPlugin extends ProgramPlugin implements OptionsChangeListener {

	/*package*/ static final String NAME = "Function Call Graph";
	/*package*/ static final String SHOW_PROVIDER_ACTION_NAME = "Display Function Call Graph";
	/*package*/ static final HelpLocation DEFAULT_HELP =
		new HelpLocation(FunctionCallGraphPlugin.class.getSimpleName(),
			FunctionCallGraphPlugin.class.getSimpleName());

	private FcgProvider connectedProvider;
	private List<FcgProvider> disconnectedProviders = new ArrayList<>();
	private FcgOptions fcgOptions = new FcgOptions();

	// enough time for users to click around without the graph starting its work
	private static final int MIN_UPDATE_DELAY = 750;
	private SwingUpdateManager locationUpdater = new SwingUpdateManager(MIN_UPDATE_DELAY, () -> {
		doLocationChanged();
	});

	public FunctionCallGraphPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {

		connectedProvider = new FcgProvider(this, true);
		createActions();

		initializeOptions();
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);
		options.addOptionsChangeListener(this);

		HelpLocation help = new HelpLocation(getName(), "Options");

		Options callGraphOptions = options.getOptions(NAME);
		fcgOptions.registerOptions(callGraphOptions, help);
		fcgOptions.loadOptions(callGraphOptions);
		connectedProvider.optionsChanged();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {

		Options callGraphOptions = options.getOptions(NAME);
		fcgOptions.loadOptions(callGraphOptions);
		connectedProvider.optionsChanged();
	}

	@Override
	public void writeConfigState(SaveState state) {
		connectedProvider.writeConfigState(state);
	}

	@Override
	public void readConfigState(SaveState state) {
		connectedProvider.readConfigState(state);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		locationUpdater.update();
	}

	private void doLocationChanged() {
		connectedProvider.locationChanged(getCurrentLocation());
	}

	void handleProviderLocationChanged(FcgProvider provider, ProgramLocation location) {
		if (provider != connectedProvider) {
			return;
		}

		GoToService goTo = tool.getService(GoToService.class);
		if (goTo == null) {
			return;
		}

		// do later so the current event processing can finish
		Swing.runLater(() -> {
			goTo.goTo(location);
		});
	}

	@Override
	protected void dispose() {
		removeProvider(connectedProvider);
		for (FcgProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}

		currentProgram = null;
	}

	private void createActions() {
		DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				connectedProvider.setVisible(true);
			}
		};

		tool.addAction(showProviderAction);
	}

	void showProvider() {
		connectedProvider.setVisible(true);
	}

	FcgProvider getProvider() {
		return connectedProvider;
	}

	Address getCurrentAddress() {
		if (currentLocation == null) {
			return null;
		}
		return currentLocation.getAddress();
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	FcgOptions getOptions() {
		return fcgOptions;
	}

	FcgProvider createNewDisconnecedProvider() {
		FcgProvider provider = new FcgProvider(this, false);
		disconnectedProviders.add(provider);
		tool.showComponentProvider(provider, true);
		return provider;
	}

	void closeProvider(FcgProvider fcgProvider) {
		disconnectedProviders.remove(fcgProvider);
		removeProvider(fcgProvider);
	}

	private void removeProvider(FcgProvider provider) {
		if (provider == null) {
			return;
		}
		provider.dispose();
		tool.removeComponentProvider(provider);
	}

}
