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

import javax.swing.KeyStroke;

import docking.*;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import help.HelpService;

/**
 * A base system action used for actions that show help information.
 */
public abstract class AbstractHelpAction extends DockingAction {

	public AbstractHelpAction(String name, KeyStroke keyStroke, boolean isPrimary) {
		super(name, DockingWindowManager.DOCKING_WINDOWS_OWNER, isPrimary);

		// Only the primary action will appear in the tool' key binding settings UI.  The primary
		// action can be managed by the users.  The secondary action is not managed at this time.
		if (isPrimary) {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			createSystemKeyBinding(keyStroke);
		}

		setEnabled(true);

		// Help actions don't have help
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	protected abstract boolean isInfo();

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DockingActionIf mouseOverAction = DockingWindowManager.getMouseOverAction();
		if (mouseOverAction != null) {
			showHelp(mouseOverAction);
			return;
		}

		Object mouseOverObject = DockingWindowManager.getMouseOverObject();
		Object helpObject = getFirstAvailableObjectThatHasHelp(mouseOverObject);
		if (helpObject != null) {
			showHelp(helpObject);
			return;
		}

		// some components are special in that they have help registered just for them
		Object eventSource = context.getSourceObject();
		helpObject = getFirstAvailableObjectThatHasHelp(eventSource);
		if (helpObject != null) {
			showHelp(helpObject);
			return;
		}

		// dialogs help is handled differently than core Ghidra components
		DialogComponentProvider dialogProvider = findDialogComponentProvider();
		if (dialogProvider != null) {
			showHelp(dialogProvider.getComponent());
			return;
		}

		// handle our 'normal' CompentProviders...just use the focused provider
		DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
		ComponentPlaceholder info = windowManager.getFocusedComponent();
		if (info != null) {
			ComponentProvider componentProvider = info.getProvider();
			showHelp(componentProvider);
			return;
		}
	}

	private void showHelp(Object helpObject) {

		SystemUtilities.runSwingLater(() -> {
			DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
			Component component = windowManager.getActiveComponent();
			DockingWindowManager.getHelpService().showHelp(helpObject, isInfo(), component);
		});
	}

	private DialogComponentProvider findDialogComponentProvider() {
		KeyboardFocusManager keyboardFocusManager =
			KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window activeWindow = keyboardFocusManager.getActiveWindow();
		if (activeWindow instanceof DockingDialog) {
			DockingDialog dockingDialog = (DockingDialog) activeWindow;
			return dockingDialog.getDialogComponent();
		}
		return null;
	}

	private Object getFirstAvailableObjectThatHasHelp(Object startingHelpObject) {
		if (startingHelpObject == null) {
			return null;
		}

		// First see if help exists for the given component directly...                
		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation helpLocation = helpService.getHelpLocation(startingHelpObject);
		if (helpLocation != null) {
			return startingHelpObject;
		}

		// Second, with no help registered for the starting component, start looking for a suitable
		// help proxy.
		//
		// For Components, we can walk their containment hierarchy to find a potential help object
		if (!(startingHelpObject instanceof Component)) {
			// not a Component; don't know how to find a better help object 
			return null;
		}

		return getFirstAvailableComponentThatHasHelp((Component) startingHelpObject);
	}

	private Component getFirstAvailableComponentThatHasHelp(Component component) {
		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation helpLocation = helpService.getHelpLocation(component);
		if (helpLocation != null) {
			return component;
		}

		Container parent = component.getParent();
		if (parent == null) {
			// nothing else to check
			return null;
		}

		return getFirstAvailableComponentThatHasHelp(parent);
	}
}
