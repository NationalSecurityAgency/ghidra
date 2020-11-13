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
package docking.actions;

import docking.Tool;
import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.widgets.table.GTable;

/**
 * A place used to hold {@link DockingActionIf}s that are meant to be used by components.  Some
 * components do not have access to the tool that is required to register their actions.  This
 * class helps those components by enabling the installation of shared actions for those 
 * components. 
 */
public class SharedActionRegistry {

	/**
	 * Install all known shared actions into the given tool
	 * @param tool the tool
	 * @param toolActions the tool action manager
	 */
	public static void installSharedActions(Tool tool, ToolActions toolActions) {
		GTable.createSharedActions(tool, toolActions, ToolConstants.SHARED_OWNER);
	}
}
