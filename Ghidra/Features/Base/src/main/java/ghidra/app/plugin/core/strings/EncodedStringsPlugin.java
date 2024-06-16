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
package ghidra.app.plugin.core.strings;

import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CharsetInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search For Encoded Strings",
	description = "Searches for strings using a specific character set and allows filtering " + 
			"results using the Unicode scripts (alphabets) used and other criteria.  This feature " +
			"is being evaluated for it's effectiveness.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class EncodedStringsPlugin extends ProgramPlugin {
	private static final String ACTIONNAME = "Search For Encoded Strings";
	static final String STRINGS_OPTION_NAME = "Strings";
	static final String CHARSET_OPTIONNAME = "Default Charset";
	static final String CHARSET_DEFAULT_VALUE = CharsetInfo.USASCII;
	static final String TRANSLATE_SERVICE_OPTIONNAME = "Default Translation Service Name";
	static final String STRINGMODEL_FILENAME_OPTIONNAME = "Default String Model Filename";
	static final String STRINGMODEL_FILENAME_DEFAULT = "stringngrams/StringModel.sng";
	static final HelpLocation HELP_LOCATION =
		new HelpLocation(HelpTopics.SEARCH, "Encoded_Strings_Dialog");

	private WeakSet<EncodedStringsDialog> openDialogs =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();
	private DockingAction searchForEncodedStringsAction;

	public EncodedStringsPlugin(PluginTool tool) {
		super(tool);
	}

	public DockingAction getSearchForEncodedStringsAction() {
		return searchForEncodedStringsAction;
	}

	@Override
	protected void init() {
		super.init();
		registerOptions();
		createActions();
	}

	private void registerOptions() {
		ToolOptions options = tool.getOptions(STRINGS_OPTION_NAME);
		options.registerOption(CHARSET_OPTIONNAME, CHARSET_DEFAULT_VALUE, HELP_LOCATION,
			"Name of default charset.");
		options.registerOption(STRINGMODEL_FILENAME_OPTIONNAME, STRINGMODEL_FILENAME_DEFAULT,
			HELP_LOCATION,
			"Name of default string model file.");
		options.registerOption(TRANSLATE_SERVICE_OPTIONNAME, "", HELP_LOCATION,
			"Name of default translation service.");
	}

	@Override
	protected void programClosed(Program program) {
		for (EncodedStringsDialog openDialog : openDialogs) {
			openDialog.programClosed(program);
		}
	}

	void dialogClosed(EncodedStringsDialog dialog) {
		openDialogs.remove(dialog);
	}

	private void createActions() {
		searchForEncodedStringsAction =
			new ActionBuilder(ACTIONNAME, getName()) // menu
					.withContext(NavigatableActionContext.class, true)
					.onAction(this::showSearchForEncodedStrings)
					.enabledWhen(ac -> ac.getLocation() != null)
					.menuPath(ToolConstants.MENU_SEARCH, "For Encoded Strings...")
					.menuGroup("search for", "Strings2")
					.helpLocation(HELP_LOCATION)
					.buildAndInstall(tool);
	}

	private void showSearchForEncodedStrings(NavigatableActionContext lac) {
		AddressSetView addrs = lac.hasSelection()
				? lac.getSelection()
				: lac.getProgram().getMemory().getAllInitializedAddressSet();
		EncodedStringsDialog dlg = new EncodedStringsDialog(this, lac.getProgram(), addrs);
		openDialogs.add(dlg);
		DockingWindowManager.showDialog(dlg);
	}

}
