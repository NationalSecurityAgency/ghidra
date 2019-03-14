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

import java.beans.PropertyChangeListener;
import java.util.Set;

import javax.swing.*;

import docking.ActionContext;
import docking.help.HelpDescriptor;

public interface DockingActionIf extends HelpDescriptor {
	public static final String ENABLEMENT_PROPERTY = "enabled";
	public static final String GLOBALCONTEXT_PROPERTY = "globalContext";
	public static final String DESCRIPTION_PROPERTY = "description";
	public static final String KEYBINDING_DATA_PROPERTY = "KeyBindings";
	public static final String MENUBAR_DATA_PROPERTY = "MenuBar";
	public static final String POPUP_MENU_DATA_PROPERTY = "PopupMenu";
	public static final String TOOLBAR_DATA_PROPERTY = "ToolBar";

	/**
	 * Returns the name of the action.
	 */
	public abstract String getName();

	/**
	 * Returns the owner of this action.  
	 */
	public abstract String getOwner();

	/**
	 * Returns a short description of this action. Generally used for a tooltip.
	 */
	public abstract String getDescription();

	/**
	 * Adds a listener to be notified if any property changes.
	 * @param listener The property change listener that will be notified of
	 *        property change events.
	 * @see   AbstractAction#addPropertyChangeListener(java.beans.PropertyChangeListener)
	 */
	public abstract void addPropertyChangeListener(PropertyChangeListener listener);

	/**
	 * Removes a listener to be notified of property changes.
	 * 
	 * @param listener The property change listener that will be notified of
	 *        property change events.
	 * @see   #addPropertyChangeListener(PropertyChangeListener)
	 * @see   AbstractAction#addPropertyChangeListener(java.beans.PropertyChangeListener)
	 */
	public abstract void removePropertyChangeListener(PropertyChangeListener listener);

	/**
	 * Enables or disables the action.
	 *
	 * @param newValue  true to enable the action, false to
	 *                  disable it
	 */
	public boolean setEnabled(boolean newValue);

	/**
	 * Returns true if the action is enabled.
	 *
	 * @return true if the action is enabled, false otherwise
	 */
	public boolean isEnabled();

	/**
	 * Returns the {@link MenuData} to be used to put this action in the menu bar.  The MenuData will be
	 * null if the action in not set to be in the menu bar.
	 * @return the {@link MenuData} for the menu bar or null if the action is not in the menu bar.
	 */
	public MenuData getMenuBarData();

	/**
	 * Returns the {@link MenuData} to be used to put this action in a popup menu.  The MenuData will be
	 * null if the action in not set to be in a popup menu.
	 * @return the {@link MenuData} for a popup menu or null if the action is not to be in a popup menu.
	 */
	public MenuData getPopupMenuData();

	/**
	 * Returns the {@link ToolBarData} to be used to put this action in a toolbar.  The ToolBarData will be
	 * null if the action in not set to be in a tool bar.
	 * @return the {@link ToolBarData} for the popup menu or null if the action is not in a popup menu.
	 */
	public ToolBarData getToolBarData();

	/**
	 * Returns the {@link KeyBindingData} to be used to assign this action to a key binding.  The 
	 * KeyBindingData will be null if the action is not set to have a keyBinding.
	 * @return the {@link KeyBindingData} for the action or null if the action does not have a keyBinding.
	 */
	public KeyBindingData getKeyBindingData();

	/**
	 * Returns the default {@link KeyBindingData} to be used to assign this action to a 
	 * key binding.  The KeyBindingData will be null if the action is not set to have a keyBinding.
	 * @return the {@link KeyBindingData} for the action or null if the action does not have a keyBinding.
	 */
	public KeyBindingData getDefaultKeyBindingData();

	/**
	 * Convenience method for getting the keybinding for this action.
	 * @return the {@link KeyStroke} to be used as a keybinding for this action or null if there is no 
	 * 
	 */
	public KeyStroke getKeyBinding();

	/**
	 * Returns the full name (the action name combined with the owner name)
	 */
	public abstract String getFullName();

	/**
	 * method to actually perform the action logic for this action.
	 * @param context the {@link ActionContext} object that provides information about where and how
	 * this action was invoked.
	 */
	public abstract void actionPerformed(ActionContext context);

	/**
	 * method is used to determine if this action should be displayed on the current popup.  This 
	 * method will only be called if the action has popup {@link PopupMenuData} set.
	 * <p>
	 * Generally, actions don't need to override this method as the default implementation will 
	 * defer to the {@link #isEnabledForContext()}, which will have the effect of adding the
	 * action to the popup only if it is enabled for a given context.  By overriding this method,
	 * you can change this behavior so that the action will be added to the popup, even if it is
	 * disabled for the context, by having this method return true even if the 
	 * {@link #isEnabledForContext()} method will return false, resulting in the action appearing
	 * in the popup menu, but begin disabled.
	 * 
	 * @param context the {@link ActionContext} from the active provider.
	 * @return true if this action is appropriate for the given context.
	 */
	public abstract boolean isAddToPopup(ActionContext context);

	/**
	 * Method that actions implement to indicate if this action is valid (knows how to work with, is
	 * appropriate for) for the given context.  This method is used
	 * to determine if the action should be enabled based on the either the local context or the
	 * global context.  The action is first asked if it is valid for the local context and if not,
	 * then it is asked if it is valid for the global context.  If a context is valid, then it will
	 * then be asked if it is enabled for that context.
	 * 
	 * @param context the {@link ActionContext} from the active provider.
	 * @return true if this action is appropriate for the given context.
	 */
	public abstract boolean isValidContext(ActionContext context);

	/**
	 * Method that actions implement to indicate if this action is valid (knows how to work with, is
	 * appropriate for) for the given global context.  This method is just like the isValidContext
	 * and in fact calls that method by default.  Many actions will work with either the active
	 * provider context or the global (the main listing) context if the local context is not valid.
	 * If you want a global action to only work on the global context, then override this method
	 * and return false.
	 * 
	 * @param context the global {@link ActionContext} from the active provider.
	 * @return true if this action is appropriate for the given context.
	 */
	public abstract boolean isValidGlobalContext(ActionContext globalContext);

	/**
	 * Method used to determine if this action should be enabled for the given context.  
	 * <p>
	 * <b>This is the method implementors override to control when the action may be used.</b>
	 * <p>
	 * This method
	 * will be called by the DockingWindowManager for actions on the global menuBar and toolBar
	 * and for actions that have a keyBinding. 
	 * <p>
	 * This method will be called whenever
	 * one of the following events occur: 
	 * <ol>
	 *    <li>when the user invokes the action via its keyBinding,</li>
	 *    <li>the user changes focus from one component provider to another,</li>  
	 * 	  <li>the user moves a component to another position in the window or into another window,</li> 
	 *    <li>a component provider reports a change in it's context,</li> 
	 *    <li>any plugin or software component reports a general change in context (calls the 
	 * tool.contextChanged(ComponentProvider) with a null parameter).</li>
	 * </ol>
	 *  The default implementation will simply return this action's enablement state.
	 *   
	 * 
	 * @param context the current {@link ActionContext} for the window.
	 * @return true if the action should be enabled for the context or false otherwise.
	 */
	public abstract boolean isEnabledForContext(ActionContext context);

	/**
	 * Returns a string that includes source file and line number information of where this action was
	 * created.
	 */
	public abstract String getInceptionInformation();

	/**
	 * Returns a JButton that is suitable for this action.  For example, It creates a ToggleButton
	 * if the action is a {@link ToggleDockingActionIf}.
	 * @return a JButton to be used in a toolbar or null if the action does not have ToolBarData set.
	 */
	public JButton createButton();

	/**
	 * Returns a JMenuItem that is suitable for this action.  For example, if the action is a 
	 * {@link ToggleDockingActionIf}, then a JCheckBoxMenuItem will be created.
	 * @param isPopup true if the action should use its Popup MenuData, else it uses the MenuBar MenuData.
	 * @return a JMenuItem for placement in either the menu bar or a popup menu.
	 */
	public JMenuItem createMenuItem(boolean isPopup);

	/**
	 * Determines whether this action should be added to a window (either the main window or a
	 * secondary detached window).  By default, this method will return true for the main window
	 * and false otherwise.  Actions that want to also appear in other windows should override this
	 * method to return true when appropriate for the context types
	 * @param isMainWindow true if the window in question is the main window. Otherwise, the window
	 * is a secondary window.
	 * @param contextTypes a list of contextTypes (Classes) based on the providers that are currently
	 * in the window.
	 * @return true if this action should be added to the window, false otherwise.
	 */
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes);

	/**
	 * Returns true if this action can have its keybinding information changed by the user.  
	 * @return true if this action can have its keybinding information changed by the user.
	 */
	public boolean isKeyBindingManaged();

	/**
	 * Sets the {@link KeyBindingData} on an action to either assign a keybinding or remove it
	 *  (keyBindingData = null).
	 * @param keyBindingData if non-null, assigns a keybinding to the action. Otherwise, removes
	 * any keybinding from the action.
	 */
	public abstract void setKeyBindingData(KeyBindingData keyBindingData);

	/**
	 * <b>Users creating actions should not call this method, but should instead call
	 * {@link #setKeyBindingData(KeyBindingData)}.</b>
	 * <p>
	 * Call this method when you wish to bypass the validation of 
	 * {@link #setKeyBindingData(KeyBindingData)} so that keybindings are set exactly as they
	 * are given.
	 * 
	 * @param newKeyBindingData the KeyBindingData to be used to assign this action to a keybinding.
	 * @param validate true signals that this method should convert keybindings to their 
	 *                 OS-dependent form (for example, on Mac a <tt>Ctrl</tt> 
	 *                 key is changed to the <tt>Command</tt> key).
	 */
	public abstract void setUnvalidatedKeyBindingData(KeyBindingData newKeyBindingData);

}
