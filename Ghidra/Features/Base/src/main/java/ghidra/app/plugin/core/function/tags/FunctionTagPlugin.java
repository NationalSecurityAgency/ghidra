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
package ghidra.app.plugin.core.function.tags;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Plugin for managing function tags. This works with the associated
 * {@link FunctionTagProvider} to allow users to view and 
 * edit function tags both globally and for individual functions.
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Create, edit, and delete function tags",
	description = "This provides actions for creating, editing, and deleting function tags"
)
//@formatter:on
public class FunctionTagPlugin extends ProgramPlugin {

	public final static String FUNCTION_TAG_MENU_SUBGROUP = "TagFunction";

	// Action visible when right-clicking on a function in the listing.
	private EditFunctionTagsAction editFunctionTagsAction;

	// The display object for this plugin.
	private FunctionTagProvider provider;

	public FunctionTagPlugin(PluginTool tool) {
		super(tool, true, false);
		provider = new FunctionTagProvider(this, getCurrentProgram());
		createActions();
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Returns the component provider for this plugin
	 * 
	 * @return the component provider
	 */
	public FunctionTagProvider getProvider() {
		return provider;
	}

	@Override
	public void init() {
		super.init();
	}

	/******************************************************************************
	 * PROTECTED METHODS
	 ******************************************************************************/

	@Override
	protected void programDeactivated(Program program) {
		provider.programDeactivated(program);
	}

	@Override
	protected void programActivated(Program program) {
		provider.programActivated(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.locationChanged(loc);
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	private void createActions() {
		editFunctionTagsAction = new EditFunctionTagsAction("Edit Function Tags", this);
		tool.addAction(editFunctionTagsAction);
	}
}
