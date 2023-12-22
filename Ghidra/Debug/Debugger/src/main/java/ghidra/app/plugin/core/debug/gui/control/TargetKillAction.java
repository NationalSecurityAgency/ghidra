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
package ghidra.app.plugin.core.debug.gui.control;

import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.debug.api.target.ActionName;
import ghidra.util.HelpLocation;

interface TargetKillAction extends ControlAction {
	String NAME = "Kill";
	String DESCRIPTION = "Kill the target";
	Icon ICON = DebuggerResources.ICON_KILL;
	String HELP_ANCHOR = "target_kill";
	int SUB_GROUP = 2;
	KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_K,
		KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);

	static TargetActionBuilder builder(DebuggerControlPlugin owner) {
		String ownerName = owner.getName();
		return new TargetActionBuilder(NAME, owner)
				.action(ActionName.KILL)
				.toolBarIcon(ICON)
				.toolBarGroup(GROUP, ControlAction.intSubGroup(SUB_GROUP))
				.keyBinding(KEY_BINDING)
				.defaultDescription(DESCRIPTION)
				.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
	}
}
