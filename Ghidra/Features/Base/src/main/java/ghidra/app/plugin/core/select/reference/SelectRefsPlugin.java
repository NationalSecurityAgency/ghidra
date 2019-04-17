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
package ghidra.app.plugin.core.select.reference;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;
import docking.action.DockingAction;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Select References",
	description = "This plugin selects references to or from the current location or selection."
)
//@formatter:on
public class SelectRefsPlugin extends Plugin {

	private DockingAction forwardAction;
	private DockingAction backwardAction;

	public SelectRefsPlugin(PluginTool tool){
		super(tool);
		setupActions();
	}

	@Override
    public void dispose(){
        tool.removeAction(forwardAction);
        tool.removeAction(backwardAction);
        
		forwardAction=null;
		backwardAction=null;
	}

	
	private void setupActions(){
		forwardAction = new SelectForwardRefsAction(tool, getName());
		backwardAction = new SelectBackRefsAction(tool, getName());
		tool.addAction(forwardAction);
		tool.addAction(backwardAction);
	}


}
