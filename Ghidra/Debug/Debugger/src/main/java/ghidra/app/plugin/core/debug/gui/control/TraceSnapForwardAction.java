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
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;

interface TraceSnapForwardAction extends ControlAction {
	String NAME = "Trace Snapshot Forward";
	String DESCRIPTION = "Navigate the trace recording forward one snapshot";
	Icon ICON = DebuggerResources.ICON_SNAP_FORWARD;
	String HELP_ANCHOR = "trace_snap_backward";
	int SUB_GROUP = 11;
	KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_F8, 0);

	static ActionBuilder builder(Plugin owner) {
		String ownerName = owner.getName();
		return new ActionBuilder(NAME, ownerName)
				.description(DESCRIPTION)
				.toolBarIcon(ICON)
				.toolBarGroup(GROUP, ControlAction.intSubGroup(SUB_GROUP))
				.keyBinding(KEY_BINDING)
				.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
	}
}
