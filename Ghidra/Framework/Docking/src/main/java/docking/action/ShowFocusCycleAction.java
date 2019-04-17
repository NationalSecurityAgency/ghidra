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

import java.awt.*;

import javax.swing.JFrame;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.ActionContext;
import docking.DockingWindowManager;
import ghidra.util.ReservedKeyBindings;

public class ShowFocusCycleAction extends DockingAction {
	static final Logger log = LogManager.getLogger(ShowFocusCycleAction.class);

	public ShowFocusCycleAction() {
		super("Show Focus Cycle", DockingWindowManager.DOCKING_WINDOWS_OWNER, false);
		createReservedKeyBinding(ReservedKeyBindings.FOCUS_CYCLE_INFO_KEY);
		setEnabled(true);

		// System action; no help needed
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		log.trace("====================================");

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusOwner = kfm.getFocusOwner();
		if (focusOwner != null) {
			Container focusRoot = focusOwner.getFocusCycleRootAncestor();
			FocusTraversalPolicy policy = focusRoot.getFocusTraversalPolicy();
			log.trace("FocusCycleRoot: " + focusRoot);
			log.trace("FocusTraversalPolicy: " + policy.getClass().getName() + ": " +
				System.identityHashCode(policy));
			Component nextComponent = policy.getFirstComponent(focusRoot);
			Component firstComponent = nextComponent;
			log.trace("\tfirst component: " + printComp(nextComponent));
			while ((nextComponent =
				policy.getComponentAfter(focusRoot, nextComponent)) != firstComponent) {
				log.trace("\tcomponent: " + printComp(nextComponent));
			}
		}
		else {
			log.trace("No focus Owner");
		}

		log.trace("");
	}

	private String printComp(Component comp) {
		if (comp == null) {
			return null;
		}

		if (comp instanceof JFrame) {
			JFrame frame = (JFrame) comp;
			return "Window (" + frame.getTitle() + "): " + System.identityHashCode(frame);
		}

		return comp.getClass().getName() + ": " + System.identityHashCode(comp);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

}
