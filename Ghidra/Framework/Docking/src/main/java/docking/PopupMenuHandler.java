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

import javax.swing.SwingUtilities;

import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import docking.menu.MenuHandler;

public class PopupMenuHandler extends MenuHandler {

	private final ActionContext actionContext;
	private final DockingWindowManager windowManager;

	public PopupMenuHandler(DockingWindowManager windowManager, ActionContext context ) {
		this.windowManager = windowManager;
		this.actionContext = context;
	}
	
	@Override
    public void menuItemEntered(DockingActionIf action) {
		DockingWindowManager.setMouseOverAction( action );
	}

	@Override
    public void menuItemExited(DockingActionIf action) {
		DockingWindowManager.clearMouseOverHelp();
	}
	
	@Override
    public void processMenuAction(final DockingActionIf action, final ActionEvent event) {
        
		DockingWindowManager.clearMouseOverHelp();
		actionContext.setSourceObject(event.getSource());
		
		// this gives the UI some time to repaint before executing the action
        SwingUtilities.invokeLater( new Runnable() {
            public void run() {
            	windowManager.setStatusText("");
            	if (action.isEnabledForContext(actionContext)) {
            		if (action instanceof ToggleDockingActionIf) {
            			ToggleDockingActionIf toggleAction = ((ToggleDockingActionIf)action);
            			toggleAction.setSelected(!toggleAction.isSelected());
            		}
            		action.actionPerformed(actionContext);
            	}
            }
        } );
	}


}
