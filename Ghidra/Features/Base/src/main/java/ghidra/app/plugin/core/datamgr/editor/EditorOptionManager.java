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
package ghidra.app.plugin.core.datamgr.editor;

import ghidra.app.plugin.core.compositeeditor.StructureEditorOptionManager;
import ghidra.app.plugin.core.compositeeditor.UnionEditorOptionManager;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;

public class EditorOptionManager implements OptionsChangeListener, StructureEditorOptionManager,
		UnionEditorOptionManager {

	private final static String STRUCTURE_EDITOR_NAME = "Structure Editor";
	private final static String UNION_EDITOR_NAME = "Union Editor";
	private final static String HEX_STRUCT_NUMBERS_OPTION_NAME = STRUCTURE_EDITOR_NAME +
			Options.DELIMITER + "Show Numbers In Hex";
	private final static String HEX_UNION_NUMBERS_OPTION_NAME = UNION_EDITOR_NAME +
			Options.DELIMITER + "Show Numbers In Hex";

	private Plugin plugin;
	private boolean showStructureNumbersInHex = false;
	private boolean showUnionNumbersInHex = false;
	private String HELP_TOPIC = "DataTypeEditors";

	public EditorOptionManager(Plugin plugin) {
		this.plugin = plugin;

		initializeOptions();
	}

	private void initializeOptions() {
		HelpLocation help = new HelpLocation(HELP_TOPIC, "StructureEditorToolOptions");
		ToolOptions options = plugin.getTool().getOptions("Editors");
		options.setOptionsHelpLocation(help);
		options.getOptions(STRUCTURE_EDITOR_NAME).setOptionsHelpLocation(help);
		options.getOptions(UNION_EDITOR_NAME).setOptionsHelpLocation(help);

		options.registerOption(HEX_STRUCT_NUMBERS_OPTION_NAME, showStructureNumbersInHex, help,
			"Toggle for whether numeric values in the Structure Editor "
				+ "should be displayed in hexadecimal or decimal "
				+ "when you initially begin editing a structure.");

		options.registerOption(HEX_UNION_NUMBERS_OPTION_NAME, showUnionNumbersInHex, help,
			"Toggle for whether numeric values in the Union Editor "
				+ "should be displayed in hexadecimal or decimal "
				+ "when you initially begin editing a union.");

		setOptions(options);
		options.addOptionsChangeListener(this);
	}

	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		setOptions(options);
	}

	private void setOptions(Options options) {

		showStructureNumbersInHex =
			options.getBoolean(HEX_STRUCT_NUMBERS_OPTION_NAME, showStructureNumbersInHex);
		showUnionNumbersInHex =
			options.getBoolean(HEX_UNION_NUMBERS_OPTION_NAME, showUnionNumbersInHex);
	}

	public boolean showStructureNumbersInHex() {
		return showStructureNumbersInHex;
	}

	public boolean showUnionNumbersInHex() {
		return showUnionNumbersInHex;
	}

	public void dispose() {
		ToolOptions options = plugin.getTool().getOptions("Editors");
		options.removeOptionsChangeListener(this);
	}
}
