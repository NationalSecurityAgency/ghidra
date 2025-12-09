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
package ghidra.app.plugin.core.flowarrow;

import java.util.*;

import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ListingMarginProviderService;
import ghidra.app.util.viewer.listingpanel.ListingMarginProvider;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Plugin that has a margin provider to show the program flow.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Show arrows for execution flow",
	description = "This plugin shows arrows to graphically illustrate the flow of execution " +
		"within a function. The arrows indicate source and destination for jumps; solid lines " +
		"indicate unconditional jumps; dashed lines indicate conditional jumps.",
	servicesProvided = { ListingMarginProviderService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramLocationPluginEvent.class }
)
//@formatter:on
public class FlowArrowPlugin extends Plugin implements ListingMarginProviderService {

	private List<FlowArrowMarginProvider> providers = new ArrayList<>();

	public FlowArrowPlugin(PluginTool tool) {
		super(tool);

		getOptions();
	}

	@Override
	public ListingMarginProvider createMarginProvider() {
		FlowArrowMarginProvider provider = new FlowArrowMarginProvider(this);
		providers.add(provider);
		return provider;
	}

	@Override
	public boolean isOwner(ListingMarginProvider provider) {
		return providers.contains(provider);
	}

	void remove(FlowArrowMarginProvider provider) {
		providers.remove(provider);
	}

	List<FlowArrowMarginProvider> getProviders() {
		return Collections.unmodifiableList(providers);
	}

	@Override
	protected void dispose() {
		for (FlowArrowMarginProvider provider : new ArrayList<>(providers)) {
			provider.dispose();
		}
	}

	private void getOptions() {
		// Note: these are here merely as a convenience so users don't have to use the theme editor.
		ToolOptions opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		opt.registerThemeColorBinding(OptionsGui.FLOW_ARROW_NON_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_NON_ACTIVE.getThemeColorId(), null,
			"The color for an arrow with no endpoint at the current address");
		opt.registerThemeColorBinding(OptionsGui.FLOW_ARROW_ACTIVE.getColorOptionName(),
			OptionsGui.FLOW_ARROW_ACTIVE.getThemeColorId(), null,
			"The color for an arrow with an endpoint at the current address");
		opt.registerThemeColorBinding(OptionsGui.FLOW_ARROW_SELECTED.getColorOptionName(),
			OptionsGui.FLOW_ARROW_SELECTED.getThemeColorId(), null,
			"The color for an arrow that has been selected by the user");
	}

}
