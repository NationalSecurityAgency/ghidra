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
package ghidra.app.plugin.core.functioncompare;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Plugin that provides the actions that allow the user to compare functions using a 
 * FunctionComparisonPanel.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.DIFF,
	shortDescription = "Compare Functions",
	description = "This plugin provides actions that allow you to compare two or more functions with each other.",
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class FunctionComparisonPlugin extends ProgramPlugin implements DomainObjectListener {

	public final static String FUNCTION_MENU_SUBGROUP = "Function";
	static final String MENU_PULLRIGHT = "CompareFunctions";
	static final String POPUP_MENU_GROUP = "CompareFunction";
	private FunctionComparisonProviderManager functionComparisonManager;

	/**
	 * Creates a plugin that provides actions for comparing functions.
	 * @param tool the tool that owns this plugin.
	 */
	public FunctionComparisonPlugin(PluginTool tool) {
		super(tool, true, true);

		functionComparisonManager = new FunctionComparisonProviderManager(this);

		tool.setMenuGroup(new String[] { MENU_PULLRIGHT }, POPUP_MENU_GROUP);
	}

	@Override
	protected void init() {
		createActions();
	}

	private void createActions() {
		tool.addAction(new CompareFunctionsAction(this));
	}

	@Override
	public void dispose() {
		functionComparisonManager.dispose();
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programClosed(Program program) {
		functionComparisonManager.closeProviders(program);
		program.removeListener(this);
	}

	/**
	 * Displays a panel for comparing the specified functions.
	 * @param functions the functions that are used to populate both the left and right side
	 * of the function comparison panel.
	 */
	void showFunctionComparisonProvider(Function[] functions) {
		functionComparisonManager.showFunctionComparisonProvider(functions);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			functionComparisonManager.domainObjectRestored(ev);
		}
	}
}
