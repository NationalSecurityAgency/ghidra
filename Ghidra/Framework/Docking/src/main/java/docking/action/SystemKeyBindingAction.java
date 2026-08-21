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
package docking.action;

import java.awt.Component;
import java.awt.event.ActionEvent;

import javax.help.UnsupportedOperationException;
import javax.swing.KeyStroke;

import docking.*;

/**
 * An {@link DockingKeyBindingAction} to signal that the given {@link DockingAction} gets priority
 * over all other non-system actions in the system.
 */
public class SystemKeyBindingAction extends DockingKeyBindingAction {

	SystemKeyBindingAction(Tool tool, DockingActionIf action, KeyStroke keyStroke) {
		super(tool, action, keyStroke);
	}

	public DockingActionIf getAction() {
		return dockingAction;
	}

	private ActionContext getContext(Component focusOwner) {
		ComponentProvider provider = tool.getActiveComponentProvider();
		ActionContext context = getLocalContext(provider);
		context.setSourceObject(focusOwner);
		return context;
	}

	@Override
	public boolean isSystemKeybindingPrecedence() {
		return true;
	}

	@Override
	public ExecutableAction getExecutableAction(Component focusOwner) {
		ActionContext context = getContext(focusOwner);
		return new SystemExecutableAction(dockingAction, context);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// A vestige from when we used to send this class through the Swing API.  Execution is now
		// done on the ExecutableAction this class creates.
		throw new UnsupportedOperationException();
	}

}
