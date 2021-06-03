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
import java.awt.KeyboardFocusManager;

import javax.swing.JButton;
import javax.swing.JFrame;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.*;
import ghidra.util.ReservedKeyBindings;

public class ShowFocusInfoAction extends DockingAction {
	static final Logger log = LogManager.getLogger(ShowFocusInfoAction.class);

	public ShowFocusInfoAction() {
		super("Show Focus Info", DockingWindowManager.DOCKING_WINDOWS_OWNER, false);
		createReservedKeyBinding(ReservedKeyBindings.FOCUS_INFO_KEY);
		setEnabled(true);

		// System action; no help needed
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		printFocusInformation();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	/**
	 * Prints to standard error the current focus information (active window, 
	 * focused component, etc.).
	 */
	private static void printFocusInformation() {
		DockingWindowManager winMgr = DockingWindowManager.getActiveInstance();
		ComponentPlaceholder info = winMgr.getFocusedComponent();
		DockableComponent dockableComp = null;
		if (info != null) {
			dockableComp = info.getComponent();
		}

		log.info("====================================");
		log.info("Active Docking Window Manager: " + winMgr.getRootFrame().getTitle() + ": " +
			System.identityHashCode(winMgr.getRootFrame()));
		if (info != null) {
			log.info("Focused Docking Window: " + info.getTitle() + ": " +
				System.identityHashCode(dockableComp));
		}
		else {
			log.info("Focused Docking Window: null");
		}

		log.info("");

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		log.info("Active Java Window: " + printComp(kfm.getActiveWindow()));
		log.info("Focused Java Window: " + printComp(kfm.getFocusedWindow()));
		log.info("Focused Java Component: " + printComp(kfm.getFocusOwner()));

		Object mouseOverObject = DockingWindowManager.getMouseOverObject();
		if (mouseOverObject instanceof Component) {
			log.info("Mouse-over Object: " + printComp((Component) mouseOverObject));
		}
		log.info("");
	}

	private static String printComp(Component printComponent) {
		if (printComponent == null) {
			return null;
		}

		if (printComponent instanceof JFrame) {
			JFrame frame = (JFrame) printComponent;
			return "Window (" + frame.getTitle() + "): " + System.identityHashCode(frame);
		}
		else if (printComponent instanceof DockingDialog) {
			DockingDialog dockingDialog = (DockingDialog) printComponent;
			return "DockingDialog: " + dockingDialog.getTitle() + ": " +
				System.identityHashCode(printComponent);
		}
		else if (printComponent instanceof JButton) {
			return "JButton: " + ((JButton) printComponent).getText() + ": " +
				System.identityHashCode(printComponent);
		}

		String name = "";
		String componentName = printComponent.getName();
		if (componentName != null) {
			name = " - '" + componentName + "' ";
		}

		return printComponent.getClass().getName() + name + ": " +
			System.identityHashCode(printComponent);
	}

}
