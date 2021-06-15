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

/**
 * The base interface for clients that wish to create commands to be registered with a tool.
 * 
 * <p>An action may appear in a primary menu, a popup menu or a toolbar.   Further, an action 
 * may have a key binding assigned.
 * 
 * <p>The particular support for key bindings is defined by {@link KeyBindingType}.   Almost all
 * client actions will use the default setting of {@link KeyBindingType#INDIVIDUAL}.   To control
 * the level of key binding support, you can pass the desired {@link KeyBindingType} to the
 * base implementation of this interface.
 * 
 * <p>ActionContext is a key concept for tool actions so that they can be context sensitive if 
 * appropriate. The context provides a 
 * consistent way for plugins and components to share tool state with actions. Actions can then
 * use that context to make decisions, such as if they should be enabled or added to a popup menu.
 * The context information is also typically used when the action is invoked.  For example, an
 * action context from a table element may provide the row in a table component that is selected and
 * then a "delete table row" action can use that information to be enabled when a table selection 
 * exists and then delete that row if the action is invoked.
 * 
 * <p> To make the overall action experience more convenient for the user, action processing
 * supports the concept of a "default tool context".  This allows actions to work on a more global
 * level than just the component that is focused.  The idea is that if an action is not valid for
 * the current focused context (and it has be declared to work this way using 
 * the {@link #setSupportsDefaultToolContext(boolean)}), then it can be validated against the default 
 * tool context.  The "default tool context" is defined to be the action context of the tool's 
 * primary component.  This is primarily intended for tool-level actions which are the ones that appear
 * in the tool's main menu bar or toolbar.  This allows the tool actions to mostly work on the
 * tool's main component context regardless of what has focus, and yet still work on the  
 * focused component if appropriate (such as a snapshot of the main component).  
 */
public interface DockingActionIf extends HelpDescriptor {
	public static final String ENABLEMENT_PROPERTY = "enabled";
	public static final String GLOBALCONTEXT_PROPERTY = "globalContext";
	public static final String DESCRIPTION_PROPERTY = "description";
	public static final String KEYBINDING_DATA_PROPERTY = "KeyBindings";
	public static final String MENUBAR_DATA_PROPERTY = "MenuBar";
	public static final String POPUP_MENU_DATA_PROPERTY = "PopupMenu";
	public static final String TOOLBAR_DATA_PROPERTY = "ToolBar";

	/**
	 * Returns the name of the action
	 * @return the name
	 */
	public String getName();

	/**
	 * Returns the owner of this action
	 * @return the owner  
	 */
	public String getOwner();

	/**
	 * Returns a description of this actions owner.  For most actions this will return the 
	 * same value as {@link #getOwner()}.
	 * 
	 * @return the description
	 */
	public default String getOwnerDescription() {
		return getOwner();
	}

	/**
	 * Returns a short description of this action. Generally used for a tooltip
	 * @return the description
	 */
	public String getDescription();

	/**
	 * Adds a listener to be notified if any property changes
	 * @param listener The property change listener that will be notified of
	 *        property change events.
	 * @see  Action#addPropertyChangeListener(java.beans.PropertyChangeListener)
	 */
	public void addPropertyChangeListener(PropertyChangeListener listener);

	/**
	 * Removes a listener to be notified of property changes.
	 * 
	 * @param listener The property change listener that will be notified of
	 *        property change events.
	 * @see   #addPropertyChangeListener(PropertyChangeListener)
	 * @see  Action#addPropertyChangeListener(java.beans.PropertyChangeListener)
	 */
	public void removePropertyChangeListener(PropertyChangeListener listener);

	/**
	 * Enables or disables the action
	 *
	 * @param newValue  true to enable the action, false to disable it
	 */
	public void setEnabled(boolean newValue);

	/**
	 * Sets whether or not this action should be activated using the default tool context if the
	 * current focused provider's context is not valid for this action.  Typically, this should
	 * be set on actions that are mostly independent of which component has focus such as those
	 * on the tool's main toolbar.   
	 * 
	 * @param newValue if true, the action will be activated using the default tool context if the
	 * local context is not valid for this action.  If false, the action will only ever be
	 * activated using the focused context.
	 */
	public void setSupportsDefaultToolContext(boolean newValue);

	/**
	 * Returns true if this action can be activated using the default tool context if the focused
	 * context is invalid for this action. See {@link #setSupportsDefaultToolContext(boolean)}
	 * @return true if this action can be activated using the default tool context if the local
	 * context is invalid for this action.
	 */
	public boolean supportsDefaultToolContext();

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
	 * null if the action in not set to be in a toolbar.
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
	 * The value of this method is that which is set from a call to 
	 * {@link #setKeyBindingData(KeyBindingData)}.
	 * 
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
	 * @return the full name
	 */
	public String getFullName();

	/**
	 * method to actually perform the action logic for this action.
	 * @param context the {@link ActionContext} object that provides information about where and how
	 * this action was invoked.
	 */
	public void actionPerformed(ActionContext context);

	/**
	 * method is used to determine if this action should be displayed on the current popup.  This 
	 * method will only be called if the action has popup {@link PopupMenuData} set.
	 * <p>
	 * Generally, actions don't need to override this method as the default implementation will 
	 * defer to the {@link #isEnabledForContext(ActionContext)}, which will have the effect 
	 * of adding the action to the popup only if it is enabled for a given context.  
	 * By overriding this method,
	 * you can change this behavior so that the action will be added to the popup, even if it is
	 * disabled for the context, by having this method return true even if the 
	 * {@link #isEnabledForContext(ActionContext)} method will return false, resulting in the 
	 * action appearing in the popup menu, but begin disabled.
	 * 
	 * @param context the {@link ActionContext} from the active provider.
	 * @return true if this action is appropriate for the given context.
	 */
	public boolean isAddToPopup(ActionContext context);

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
	public boolean isValidContext(ActionContext context);

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
	public boolean isEnabledForContext(ActionContext context);

	/**
	 * Returns a string that includes source file and line number information of where 
	 * this action was created
	 * @return the inception information
	 */
	public String getInceptionInformation();

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
	 * and false otherwise. 
	 * 
	 * @param isMainWindow true if the window in question is the main window
	 * @param contextTypes a list of contextTypes (Classes) based on the providers that are currently
	 * in the window.
	 * @return true if this action should be added to the window, false otherwise.
	 */
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes);

	/**
	 * Returns this actions level of support for key binding accelerator keys
	 * 
	 * <p>Actions support key bindings by default.  Some reserved actions do not support 
	 * key bindings, while others wish to share the same key bindings with multiple, equivalent
	 * actions (this allows the user to set one binding that works in many different contexts).
	 * 
	 * @return the key binding support
	 */
	public default KeyBindingType getKeyBindingType() {
		return KeyBindingType.INDIVIDUAL;
	}

	/**
	 * Sets the {@link KeyBindingData} on an action to either assign a keybinding or remove it
	 *  (keyBindingData = null).
	 * @param keyBindingData if non-null, assigns a keybinding to the action. Otherwise, removes
	 * any keybinding from the action.
	 */
	public void setKeyBindingData(KeyBindingData keyBindingData);

	/**
	 * <b>Users creating actions should not call this method, but should instead call
	 * {@link #setKeyBindingData(KeyBindingData)}.</b>
	 * <p>
	 * Call this method when you wish to bypass the validation of 
	 * {@link #setKeyBindingData(KeyBindingData)} so that keybindings are set exactly as they
	 * are given (such as when set by the user and not by the programmer).
	 * 
	 * @param newKeyBindingData the KeyBindingData to be used to assign this action to a keybinding
	 */
	public void setUnvalidatedKeyBindingData(KeyBindingData newKeyBindingData);

	/**
	 * Called when the action's owner is removed from the tool
	 */
	public void dispose();
}
