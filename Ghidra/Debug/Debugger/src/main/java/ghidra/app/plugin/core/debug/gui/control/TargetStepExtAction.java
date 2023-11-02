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

import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.util.HelpLocation;

interface TargetStepExtAction extends ControlAction {
	Icon ICON = DebuggerResources.ICON_STEP_LAST;
	String HELP_ANCHOR = "target_step_ext";
	int SUB_GROUP = 9;
	KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, KeyEvent.CTRL_DOWN_MASK);

	static ActionBuilder builder(String name, DebuggerControlPlugin owner) {
		String ownerName = owner.getName();
		return new ActionBuilder(name, ownerName)
				.toolBarIcon(ICON)
				.toolBarGroup(GROUP, ControlAction.intSubGroup(SUB_GROUP) + name)
				.keyBinding(KEY_BINDING)
				.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
	}
}
