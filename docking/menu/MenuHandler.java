/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.awt.event.ActionEvent;

import javax.swing.event.*;

import docking.action.DockingActionIf;

/**
 * <code>MenuHandler</code> provides a listener interface for menus.
 * This interface has been provided to allow the listener to
 * manage focus and help behavior.
 */
public abstract class MenuHandler implements MenuListener, PopupMenuListener {
	
	/**
	 * Invoked when a menu action item is selected.
	 * @param action associated action.
	 * @param event event details.
	 */
	public void processMenuAction(final DockingActionIf action, final ActionEvent event) {
	}
	
	/**
	 * Invoked when the mouse highlights a menu item.
	 * @param action associated action.
	 */
	public void menuItemEntered(DockingActionIf action) {
	}
	
	/**
	 * Invoked when the mouse exits a menu item.
	 * @param action associated action.
	 */
	public void menuItemExited(DockingActionIf action) {
	}
	
	/**
	 * Invoked when a menu is cancelled (not sure if this is ever invoked)
	 * @see javax.swing.event.MenuListener#menuCanceled(javax.swing.event.MenuEvent)
	 */
	public void menuCanceled(MenuEvent e) {
	}

	/**
	 * Invoked when a menu is no longer selected.  This is always preceeded
	 * by a menuSelected invocation.  This is invoked prior to the processMenuAction 
	 * if an action item is selected.
	 * @see javax.swing.event.MenuListener#menuDeselected(javax.swing.event.MenuEvent)
	 */
	public void menuDeselected(MenuEvent e) {
	}

	/**
	 * Invoked when a menu is selected.
	 * @see javax.swing.event.MenuListener#menuSelected(javax.swing.event.MenuEvent)
	 */
	public void menuSelected(MenuEvent e) {
	}

	/**
	 * This method is called before the popup menu becomes visible 
	 * @see javax.swing.event.PopupMenuListener#popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent)
	 */
    public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
    }

    /**
     * This method is called before the popup menu becomes invisible
     * Note that a JPopupMenu can become invisible any time 
     * @see javax.swing.event.PopupMenuListener#popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent)
     */
    public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
    }

    /**
     * This method is called when the popup menu is canceled
     * @see javax.swing.event.PopupMenuListener#popupMenuCanceled(javax.swing.event.PopupMenuEvent)
     */
    public void popupMenuCanceled(PopupMenuEvent e) {
    }
	
}
