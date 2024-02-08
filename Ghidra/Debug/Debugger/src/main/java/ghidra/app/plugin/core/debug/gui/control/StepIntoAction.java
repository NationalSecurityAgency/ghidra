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

interface StepIntoAction extends ControlAction {
	Icon ICON = DebuggerResources.ICON_STEP_INTO;
	int SUB_GROUP = 5;
	KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, 0);
}
