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
package ghidra.app.plugin.core.symboltree.actions;

import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.util.HTMLUtilities;
import resources.Icons;

public class GoToToggleAction extends ToggleDockingAction {

	public GoToToggleAction(SymbolTreePlugin plugin) {
		super("Navigation", plugin.getName());

		setEnabled(true);
		this.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null));

		setSelected(false);
		setDescription(HTMLUtilities.toHTML("Toggle <b>On</b> means to select the symbol\n" +
			"that corresponds to the current location."));
	}
}
