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

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.navigation.GoToAddressLabelDialog;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Go To Address of Label",
	description = "This plugin provides the \"go to\" action and dialog.  When the "
			+ "action is invoked, a dialog is presented allowing the user to"
			+ " type in a label, address or \"wildcard\" string.  If multiple"
			+ " matches are found, a dialog is displayed showing all results",
			servicesRequired = { GoToService.class }
)
//@formatter:on
public class GoToAddressLabelPlugin extends Plugin implements OptionsChangeListener {

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Instance fields             										//
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	private GoToAddressLabelDialog goToDialog;
	private DockingAction action;
	// configurable properties
	private int maximumGotoEntries;
	private boolean cStyleInput;
	private boolean goToMemory;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Class fields and methods             							//
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	private static final int DEFAULT_MAX_GOTO_ENTRIES = 10;
	private static final boolean DEFAULT_C_STYLE = false;

	/**
	 * This option controls the Go To dialog's feature that remembers the last successful
	 * go to entry.
	 */
	private static final String GO_TO_MEMORY = "Goto Dialog Memory";
	private static final boolean DEFAULT_MEMORY = true;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Constructor               										//
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	public GoToAddressLabelPlugin(PluginTool pluginTool) {
		super(pluginTool);

		action = new NavigatableContextAction("Go To Address/Label", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				goToDialog.show(context.getNavigatable(), context.getAddress(), tool);
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return context.getProgram() != null;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		action.addToWindowWhen(NavigatableActionContext.class);
		action.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, action.getName()));
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, "Go To..." }, null, "GoTo",
				MenuData.NO_MNEMONIC, "2")); // second item in the menu

		action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_G, 0));

		action.setEnabled(false);

	}

	@Override
	public void init() {
		GoToService gotoService = tool.getService(GoToService.class);
		goToDialog = new GoToAddressLabelDialog(gotoService, this);
		maximumGotoEntries = DEFAULT_MAX_GOTO_ENTRIES;
		getOptions();

		tool.addAction(action);
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Configurable properties
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	public final int getMaximumGotoEntries() {
		return maximumGotoEntries;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		goToDialog.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		goToDialog.writeConfigState(saveState);
	}

	/**
	 * Notification that an option changed.
	 *
	 * @param options options object containing the property that changed
	 * @param group name of the group to which this option is associated,
	 *        null if not associated with any group
	 * @param opName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 */
	@Override
	public void optionsChanged(ToolOptions options, String opName, Object oldValue,
			Object newValue) {
		if (opName.equals(GhidraOptions.OPTION_MAX_GO_TO_ENTRIES)) {
			maximumGotoEntries =
				options.getInt(GhidraOptions.OPTION_MAX_GO_TO_ENTRIES, DEFAULT_MAX_GOTO_ENTRIES);
			if (maximumGotoEntries <= 0) {
				throw new OptionsVetoException("Search limit must be greater than 0");
			}
			goToDialog.maxEntrysChanged();
		}
		else if (opName.equals(GhidraOptions.OPTION_NUMERIC_FORMATTING)) {
			cStyleInput =
				options.getBoolean(GhidraOptions.OPTION_NUMERIC_FORMATTING, DEFAULT_C_STYLE);
			goToDialog.setCStyleInput(cStyleInput);
		}
		else if (opName.equals(GO_TO_MEMORY)) {
			goToMemory = options.getBoolean(GO_TO_MEMORY, DEFAULT_MEMORY);
			goToDialog.setMemory(goToMemory);
		}
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Overridden Plugin Methods               			     			//
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	@Override
	public void dispose() {
		ToolOptions options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.removeOptionsChangeListener(this);

		super.dispose();
	}

	private void getOptions() {
		ToolOptions opt = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		// descriptions
		opt.registerOption(GhidraOptions.OPTION_NUMERIC_FORMATTING, DEFAULT_C_STYLE, null,
			"Interpret value entered in the Go To dialog as either hex, " +
				"octal, or binary number.");
		opt.registerOption(GhidraOptions.OPTION_MAX_GO_TO_ENTRIES, DEFAULT_MAX_GOTO_ENTRIES, null,
			"Max number of entries remembered in the go to list.");
		opt.registerOption(GO_TO_MEMORY, DEFAULT_MEMORY, null,
			"Remember the last successful go to input in the " +
				"Go To dialog.  If this option is enabled, then the " +
				"Go To dialog will leave the last " +
				"successful go to input in the combo box of the Go " +
				"To dialog and will select the " + "value for easy paste replacement.");

		// options
		maximumGotoEntries =
			opt.getInt(GhidraOptions.OPTION_MAX_GO_TO_ENTRIES, DEFAULT_MAX_GOTO_ENTRIES);

		cStyleInput = opt.getBoolean(GhidraOptions.OPTION_NUMERIC_FORMATTING, DEFAULT_C_STYLE);
		goToDialog.setCStyleInput(cStyleInput);

		goToMemory = opt.getBoolean(GO_TO_MEMORY, DEFAULT_MEMORY);
		goToDialog.setMemory(goToMemory);

		opt.addOptionsChangeListener(this);
	}

	GoToAddressLabelDialog getDialog() {
		return goToDialog;
	}
}
