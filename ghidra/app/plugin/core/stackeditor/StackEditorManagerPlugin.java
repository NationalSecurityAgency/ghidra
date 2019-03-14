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
package ghidra.app.plugin.core.stackeditor;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

/**
 * Plugin to popup edit sessions for function stack frames.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Stack editor",
	description = "This plugin provides an action and dialog for editing a function's stack frame.",
	servicesRequired = { DataTypeManagerService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class StackEditorManagerPlugin extends Plugin
		implements OptionsChangeListener, StackEditorOptionManager {

	private final static String EDITOR_NAME = "Stack Editor";
	private final static String HEX_NUMBERS_OPTION_NAME =
		EDITOR_NAME + Options.DELIMITER + "Show Numbers In Hex";
	private EditStackAction editStackAction;
	private StackEditorManager editorMgr;
	private DataTypeManagerService dtmService;
	private boolean showNumbersInHex = true;
	private String HELP_TOPIC = "StackEditor";

	/**
	 * Constructor
	 */
	public StackEditorManagerPlugin(PluginTool tool) {
		super(tool);
		editorMgr = new StackEditorManager(this);
		createActions();

		ToolOptions options = tool.getOptions("Editors");
		initializeOptions(options);
		options.addOptionsChangeListener(this);
	}

	@Override
	protected void init() {
		initializeServices();
	}

	/**
	 * Initialize services used
	 */
	private void initializeServices() {

		dtmService = tool.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			throw new AssertException("DataTypeManagerService was not found!");
		}
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove itself
	 * from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		editorMgr.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program p = ((ProgramClosedPluginEvent) event).getProgram();
			editorMgr.programClosed(p);
		}
		super.processEvent(event);
	}

	/**
	 * Create the actions for the menu on the tool.
	 */
	private void createActions() {
		editStackAction = new EditStackAction(this, dtmService);
		tool.addAction(editStackAction);
	}

	@Override
	protected boolean canClose() {
		return editorMgr.canClose();
	}

	@Override
	protected void close() {
		editorMgr.close();
	}

	public void edit(Function function) {
		editorMgr.edit(function);
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		return editorMgr.canCloseDomainObject(dObj);
	}

	CompositeEditorProvider getProvider(Program pgm, String functionName) {
		return editorMgr.getProvider(pgm, functionName);
	}

	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		setOptions(options);
	}

	private void initializeOptions(Options options) {
		HelpLocation helpLocation = new HelpLocation(HELP_TOPIC, "StackEditorToolOptions");
		options.setOptionsHelpLocation(helpLocation);
		options.getOptions(EDITOR_NAME).setOptionsHelpLocation(helpLocation);

		String description =
			"Toggle for whether numeric values in the Stack Frame Editor "
				+ "should be displayed in hexadecimal or decimal "
				+ "when you initially begin editing a stack frame.";

		options.registerOption(HEX_NUMBERS_OPTION_NAME, showNumbersInHex, helpLocation, description);
	}

	private void setOptions(Options options) {
		showNumbersInHex = options.getBoolean(HEX_NUMBERS_OPTION_NAME, showNumbersInHex);
	}

	public void updateOptions() {
		Options options = tool.getOptions("Editors");
		options.setBoolean(HEX_NUMBERS_OPTION_NAME, showNumbersInHex);
	}

	public boolean showStackNumbersInHex() {
		return showNumbersInHex;
	}
}
