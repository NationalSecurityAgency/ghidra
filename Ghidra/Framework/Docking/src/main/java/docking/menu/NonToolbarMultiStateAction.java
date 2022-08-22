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
package docking.menu;

import java.awt.event.ActionListener;

import javax.swing.JButton;

import docking.action.DockingAction;
import docking.widgets.EventTrigger;
import ghidra.util.Swing;

/**
 * A class for clients that wish to create a button that has multiple states, controlled by a
 * drop-down menu.  Further, this action is not meant to be added to a toolbar.  If you wish 
 * for this action to appear in the toolbar, then extend {@link MultiStateDockingAction} 
 * instead.
 * 
 * <p>To use this class, extend it, overriding the 
 * {@link #actionStateChanged(ActionState, EventTrigger)} callback.  Call 
 * {@link #createButton()} and add the return value to your UI.
 *
 * @param <T> the type
 * @see MultiStateDockingAction
 */
public abstract class NonToolbarMultiStateAction<T> extends MultiStateDockingAction<T> {

	// A listener that will get called when the button (not the popup) is clicked.  Toolbar
	// actions do not need this functionality, since the toolbar API will call actionPerfomred().
	private ActionListener clickListener = e -> {
		actionPerformed();
	};

	public NonToolbarMultiStateAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public JButton doCreateButton() {
		JButton button = super.doCreateButton();
		button.addActionListener(clickListener);
		return button;
	}

	/**
	 * This method is called when the user clicks the button <B>when this action is used as a 
	 * custom button provider and not installed into the default {@link DockingAction} framework.
	 * </B> 
	 * 
	 * This is the callback to be overridden when the child wishes to respond to user button
	 * presses that are on the button and not the drop-down.  The default behavior is to show the
	 * popup menu when the button is clicked.
	 */
	protected void actionPerformed() {
		Swing.runLater(() -> showPopup());
	}

}
