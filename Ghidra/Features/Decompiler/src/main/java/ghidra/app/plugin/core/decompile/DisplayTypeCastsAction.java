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
package ghidra.app.plugin.core.decompile;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * An action to update the Decompiler option for disabling the display of type casts.
 */
public class DisplayTypeCastsAction extends ToggleDockingAction {

	private DecompilePlugin plugin;
	private OptionsChangeListener listener = new DisplayTypeCastsOptionsListener();

	protected DisplayTypeCastsAction(DecompilePlugin plugin) {
		super("Disable Type Casts Display", plugin.getClass().getSimpleName());
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DisplayDisableCasts"));
		setKeyBindingData(new KeyBindingData("BACK_SLASH"));

		// the menu group 'wDebug' is just above 'Debug Function Decompilation'
		setMenuBarData(new MenuData(new String[] { "Disable Type Casts" }, "wDebug"));

		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		boolean disableTypeCasts = options.getBoolean(DecompileOptions.NOCAST_OPTIONSTRING, false);
		setEnabled(disableTypeCasts);

		options.addOptionsChangeListener(listener);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		options.setBoolean(DecompileOptions.NOCAST_OPTIONSTRING, isSelected());
	}

	private class DisplayTypeCastsOptionsListener implements OptionsChangeListener {

		@Override
		public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
				Object newValue) throws OptionsVetoException {

			if (DecompileOptions.NOCAST_OPTIONSTRING.equals(optionName)) {
				Boolean optionSelected = (Boolean) newValue;
				if (isSelected() != optionSelected) {
					setSelected(optionSelected);
				}
			}
		}
	}

	@Override
	public void dispose() {
		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		options.removeOptionsChangeListener(listener);
	}
}
