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
package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.HelpLocation;

public class EditPropertiesAction extends DockingAction {
	private final static String OPTIONS_TITLE = "Decompiler";

	private final PluginTool tool;

	public EditPropertiesAction(String owner, PluginTool tool) {
		super("DecompilerProperties", owner);
		this.tool = tool;
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DisplayOptions"));
		setPopupMenuData( new MenuData( new String[]{ "Properties"}, "ZED" ) );
	}
	
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return tool.getService(OptionsService.class) != null;
	}
	
	@Override
	public void actionPerformed(ActionContext context) {
        OptionsService service = tool.getService( OptionsService.class );
        service.showOptionsDialog( OPTIONS_TITLE  + ".Display", "Decompiler" );
	}
	
}
