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
package ghidra.app.plugin.core.navigation;

import java.awt.event.KeyEvent;
import java.util.function.Consumer;

import javax.swing.KeyStroke;

import docking.*;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Component Provider Navigation",
	description = "The plugin provides actions to manage switching between Component Providers."
)
//@formatter:on
public class ProviderNavigationPlugin extends Plugin {

	static final String GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME = "Go To Last Active Component";

	private ComponentProvider previousActiveProvider;
	private ComponentProvider currentActiveProvider;
	private Consumer<ComponentProvider> providerActivator =
		provider -> tool.showComponentProvider(provider, true);

	private DockingContextListener contextListener = context -> {

		ComponentProvider componentProvider = context.getComponentProvider();
		if (componentProvider != null) {
			if (componentProvider != currentActiveProvider) {
				previousActiveProvider = currentActiveProvider;
				currentActiveProvider = componentProvider;
			}
		}
	};

	public ProviderNavigationPlugin(PluginTool tool) {
		super(tool);

		createActions();

		tool.addContextListener(contextListener);
	}

	private void createActions() {

		DockingAction previousProviderAction =
			new DockingAction(GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME, getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					providerActivator.accept(previousActiveProvider);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return previousActiveProvider != null;
				}
			};
		previousProviderAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_NAVIGATION, GO_TO_LAST_ACTIVE_COMPONENT_ACTION_NAME },
			null, ToolConstants.MENU_NAVIGATION_GROUP_WINDOWS, MenuData.NO_MNEMONIC,
			"xLowInMenuSubGroup"));
		previousProviderAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_F6, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		previousProviderAction.setHelpLocation(
			new HelpLocation("Navigation", "Navigation_Previous_Provider"));

		tool.addAction(previousProviderAction);
	}

	// for testing
	void resetTrackingState() {
		previousActiveProvider = null;
		currentActiveProvider = null;
	}

	// for testing
	void setProviderActivator(Consumer<ComponentProvider> newActivator) {
		this.providerActivator = newActivator;
	}
}
