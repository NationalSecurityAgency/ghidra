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
package ghidra.app.plugin.core.reachability;

import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import resources.ResourceManager;
import resources.icons.RotateIcon;
import docking.ActionContext;
import docking.action.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Function Reachability Plugin",
	description = "This plugin shows all paths between two functions.",
	servicesRequired = {  },
	eventsProduced = {  }
)
//@formatter:on
public class FunctionReachabilityPlugin extends ProgramPlugin {

	// TODO
	static final Icon ICON = new RotateIcon(
		ResourceManager.loadImage("images/function_graph_curvey.png"), 90);

	private DockingAction showProviderAction;
	private List<FunctionReachabilityProvider> providers =
		new ArrayList<FunctionReachabilityProvider>();

	public FunctionReachabilityPlugin(PluginTool tool) {
		super(tool, true, true);

		createActions();
	}

	private void createActions() {
		showProviderAction = new DockingAction("Show Function Reachability", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				createNewProvider(currentLocation);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return false;
				}

				ListingActionContext listingContext = (ListingActionContext) context;
				ProgramLocation location = listingContext.getLocation();
				return location instanceof FunctionSignatureFieldLocation;
			}
		};

// TODO verify Function menu positioning		
		showProviderAction.setPopupMenuData(new MenuData(new String[] { "Function",
			"Function Reachability" }, ICON, "ShowReferences"));

// TODO graph menu?...it is a graph, but not a UI graph		
		showProviderAction.setMenuBarData(new MenuData(new String[] { "Graph",
			"Function Reachability" }, ICON));

// TODO in toolbar menu?		
		showProviderAction.setToolBarData(new ToolBarData(ICON, "View"));
		showProviderAction.setHelpLocation(new HelpLocation("FunctionReachabilityPlugin",
			"Function_Reachability_Plugin"));
		tool.addAction(showProviderAction);
	}

	private void createNewProvider(ProgramLocation location) {
		FunctionReachabilityProvider provider = new FunctionReachabilityProvider(this);
		providers.add(provider);
		provider.initialize(currentProgram, location);
		tool.showComponentProvider(provider, true);
	}

	void removeProvider(FunctionReachabilityProvider provider) {
		providers.remove(provider);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		// TODO if we add 'incoming location' following, then select all paths containing location
		super.locationChanged(loc);
	}

	@Override
	protected void selectionChanged(ProgramSelection sel) {
		// TODO if we add 'incoming location' following, then select all paths containing selection		
		super.selectionChanged(sel);
	}
}
