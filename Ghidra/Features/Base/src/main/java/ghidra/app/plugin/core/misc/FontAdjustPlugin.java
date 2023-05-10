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
package ghidra.app.plugin.core.misc;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Manages the markers to display areas where changes have occurred 
 */
@PluginInfo( //@formatter:off
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Provides generic actions for increasing/decreasing fonts.",
	description = "This plugin provides actions for increasing fonts used by component providers. "+
	"ComponentProviders can either override the \"changeFontSize()\" method or register a" +
	"theme font id that can be automatically adjusted."
) //@formatter:on

public class FontAdjustPlugin extends Plugin {
	public FontAdjustPlugin(PluginTool tool) {

		super(tool);

		new ActionBuilder("Increment Font", "tool")
				.keyBinding("ctrl EQUALS")
				.onAction(this::incrementFont)
				.buildAndInstall(tool);

		new ActionBuilder("Decrement Font", "tool")
				.keyBinding("ctrl MINUS")
				.onAction(this::decrementFont)
				.buildAndInstall(tool);

		new ActionBuilder("Reset Font", "tool")
				.keyBinding("ctrl 0")
				.onAction(this::resetFontSize)
				.buildAndInstall(tool);
	}

	private void incrementFont(ActionContext context) {
		ComponentProvider provider = context.getComponentProvider();
		if (provider != null) {
			provider.adjustFontSize(true);
		}
	}

	private void decrementFont(ActionContext context) {
		ComponentProvider provider = context.getComponentProvider();
		if (provider != null) {
			provider.adjustFontSize(false);
		}
	}

	private void resetFontSize(ActionContext context) {
		ComponentProvider provider = context.getComponentProvider();
		if (provider != null) {
			provider.resetFontSize();
		}
	}
}
