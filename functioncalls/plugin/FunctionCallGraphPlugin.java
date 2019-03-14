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

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
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
public class FunctionCallGraphPlugin extends ProgramPlugin {

	/*package*/ static final String NAME = "Function Call Graph";
	/*package*/ static final String SHOW_PROVIDER_ACTION_NAME = "Display Function Call Graph";
	/*package*/ static final HelpLocation DEFAULT_HELP =
		new HelpLocation(FunctionCallGraphPlugin.class.getSimpleName(),
			FunctionCallGraphPlugin.class.getSimpleName());

	private FcgProvider provider;

	// enough time for users to click around without the graph starting its work
	private static final int MIN_UPDATE_DELAY = 750;
	private SwingUpdateManager locationUpdater = new SwingUpdateManager(MIN_UPDATE_DELAY, () -> {
		doLocationChanged();
	});

	public FunctionCallGraphPlugin(PluginTool tool) {
		super(tool, true, false);
	}

	@Override
	protected void init() {
		provider = new FcgProvider(tool, this);
		createActions();
	}

	@Override
	public void writeConfigState(SaveState state) {
		provider.writeConfigState(state);
	}

	@Override
	public void readConfigState(SaveState state) {
		provider.readConfigState(state);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		locationUpdater.update();
	}

	private void doLocationChanged() {
		provider.locationChanged(getCurrentLocation());
	}

	void handleProviderLocationChanged(ProgramLocation location) {
//		For snapshots
//		if (provider != connectedProvider) {
//			return;
//		}

		GoToService goTo = tool.getService(GoToService.class);
		if (goTo == null) {
			return;
		}

		// do later so the current event processing can finish
		SystemUtilities.runSwingLater(() -> {
			goTo.goTo(location);
		});
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}

	private void createActions() {
		DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.setVisible(true);
			}
		};

// TODO create icon from scratch: bow-tie		
//		ImageIcon icon = ResourceManager.loadImage("images/applications-development.png");
//		showProviderAction.setToolBarData(new ToolBarData(icon, "View"));
		tool.addAction(showProviderAction);
	}

	void showProvider() {
		provider.setVisible(true);
	}

	FcgProvider getProvider() {
		return provider;
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
}
