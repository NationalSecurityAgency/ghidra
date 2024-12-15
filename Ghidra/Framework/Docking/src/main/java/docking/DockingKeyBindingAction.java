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
package docking;

import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.KeyStroke;

import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;

/**
 * A class that can be used as an interface for using actions associated with keybindings. This
 * class is meant to only by used by internal Ghidra key event processing.
 */
public abstract class DockingKeyBindingAction extends AbstractAction {

	protected Tool tool;
	protected DockingActionIf dockingAction;
	protected KeyStroke keyStroke;

	public DockingKeyBindingAction(Tool tool, DockingActionIf action, KeyStroke keyStroke) {
		super(KeyBindingUtils.parseKeyStroke(keyStroke));
		this.tool = tool;
		this.dockingAction = action;
		this.keyStroke = keyStroke;
	}

	@Override
	public boolean isEnabled() {
		return true; // always enable; this is a internal action that cannot be disabled
	}

	public abstract KeyBindingPrecedence getKeyBindingPrecedence();

	public boolean isSystemKeybindingPrecedence() {
		return false;
	}

	@Override
	public void actionPerformed(final ActionEvent e) {
		tool.setStatusInfo("");
		ComponentProvider provider = tool.getActiveComponentProvider();
		ActionContext context = getLocalContext(provider);
		context.setSourceObject(e.getSource());
		dockingAction.actionPerformed(context);
	}

	public List<DockingActionIf> getValidActions(Object source) {
		return getActions(); // the action for this class is always enabled and valid
	}

	protected ActionContext getLocalContext(ComponentProvider localProvider) {
		if (localProvider == null) {
			return new DefaultActionContext();
		}

		ActionContext actionContext = localProvider.getActionContext(null);
		if (actionContext != null) {
			return actionContext;
		}

		return new DefaultActionContext(localProvider, null);
	}

	public List<DockingActionIf> getActions() {
		return List.of(dockingAction);
	}
}
