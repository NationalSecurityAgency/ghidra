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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import javax.swing.*;

import docking.*;
import docking.widgets.EmptyBorderButton;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;
import resources.icons.FileBasedIcon;
import resources.icons.ImageIconWrapper;
import utilities.util.reflection.ReflectionUtilities;

/**
 * <code>DockingAction</code> defines a user action associated with a toolbar icon and/or
 * menu item.  All actions must specify an action name which will be used to associate key bindings
 * and will be used as the popup menu item when needed.  This name should be unique across
 * the entire application.
 * <p>
 * DockingActions can be invoked from the global menu, a popup menu, a toolbar, and/or a keybinding,
 * depending on whether or not menuBarData, popupMenuData, toolBarData, and/or keyBindingData have 
 * been set.
 * <p>
 * <b> 
 * Implementors of this class should override {@link #actionPerformed(ActionContext)}.
 * </b>
 * <p>
 * Generally, implementors should also override {@link #isEnabledForContext(ActionContext)}.  This
 * method is used to determine if an action if applicable to the current context.   Overriding this
 * method allows actions to manage their own enablement.  Otherwise, the default behavior for this
 * method is to return the current enabled property of the action.  This allows for the possibility
 * for plugins to externally manage the enablement of its actions.
 * <P>
 * NOTE: If you wish to do your own external enablement management for an action (which is highly
 * discouraged), it is very important that you don't use any of the internal enablement mechanisms
 * by setting the predicates {@link #enabledWhen(Predicate)}, {@link #validContextWhen(Predicate)}
 * or overriding {@link #isValidContext(ActionContext)}. These predicates and methods trigger
 * internal enablement management which will interfere with you own calls to
 * {@link DockingAction#setEnabled(boolean)}.
 */
public abstract class DockingAction implements DockingActionIf {

	private WeakSet<PropertyChangeListener> propertyListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private final String name;
	private final String owner;
	private String description = "";
	private String inceptionInformation;

	private boolean isEnabled = true;

	private KeyBindingType keyBindingType = KeyBindingType.INDIVIDUAL;
	private KeyBindingData defaultKeyBindingData;
	private KeyBindingData keyBindingData;
	private MenuBarData menuBarData;
	private PopupMenuData popupMenuData;
	private ToolBarData toolBarData;

	private Predicate<ActionContext> enabledPredicate;
	private Predicate<ActionContext> popupPredicate;
	private Predicate<ActionContext> validContextPredicate;
	private boolean shouldAddToAllWindows = false;
	private Class<? extends ActionContext> addToWindowWhenContextClass = null;

	private boolean supportsDefaultToolContext;

	public DockingAction(String name, String owner) {
		this.name = name;
		this.owner = owner;

		recordInception();
		HelpLocation location = new HelpLocation(owner, name, inceptionInformation);
		setHelpLocation(location);
	}

	public DockingAction(String name, String owner, KeyBindingType kbType) {
		this(name, owner);
		this.keyBindingType = Objects.requireNonNull(kbType);
	}

	public DockingAction(String name, String owner, boolean supportsKeyBindings) {
		this(name, owner);
		this.keyBindingType =
			supportsKeyBindings ? KeyBindingType.INDIVIDUAL : KeyBindingType.UNSUPPORTED;
	}

	protected KeyBindingType getPreferredKeyBindingType() {
		return KeyBindingType.INDIVIDUAL;
	}

	@Override
	public abstract void actionPerformed(ActionContext context);

	@Override
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		propertyListeners.add(listener);
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		propertyListeners.remove(listener);
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public String getFullName() {
		return getName() + " (" + getOwner() + ")";
	}

	@Override
	public MenuData getMenuBarData() {
		return menuBarData;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getOwner() {
		return owner;
	}

	@Override
	public MenuData getPopupMenuData() {
		return popupMenuData;
	}

	@Override
	public ToolBarData getToolBarData() {
		return toolBarData;
	}

	@Override
	public String getInceptionInformation() {
		return inceptionInformation;
	}

	@Override
	public boolean isEnabled() {
		return isEnabled;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (popupPredicate != null) {
			return popupPredicate.test(context);
		}
		return isEnabledForContext(context);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (enabledPredicate != null) {
			return enabledPredicate.test(context);
		}
		return isEnabled();
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (validContextPredicate != null) {
			return validContextPredicate.test(context);
		}
		return true;
	}

	/**
	 * Determines if this action should be added to a window.
	 * <P>
	 * If the client wants the action on all windows, then they can call {@link #shouldAddToAllWindows}
	 * <P>
	 * If the client wants the action to be on a window only when the window can produce 
	 * a certain context type, the the client should call 
	 * {@link #addToWindowWhen(Class)}
	 * <P>
	 * Otherwise, by default, the action will only be on the main window.
	 * 
	 */
	@Override
	public final boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		// this method only applies to actions with top level menus or tool bars.
		if (menuBarData == null && toolBarData == null) {
			return false;
		}
		
		// clients can specify that the action should be on all windows.
		if (shouldAddToAllWindows) {
			return true;
		}

		// clients can specify a context class that determines if an action should
		// be added to a window.
		if (addToWindowWhenContextClass != null) {
			for (Class<?> class1 : contextTypes) {
				if (addToWindowWhenContextClass.isAssignableFrom(class1)) {
					return true;
				}
			}
			return false;
		}

		// default to only appearing in main window
		return isMainWindow;
	}

	/**
	 * Set a specific Help location for this action.
	 * This will replace the default help location
	 * @param location the help location for the action.
	 */
	public void setHelpLocation(HelpLocation location) {
		DockingWindowManager.getHelpService().registerHelp(this, location);
	}

	/**
	 * Signals the the help system that this action does not need a help entry.   Some actions
	 * are so obvious that they do not require help, such as an action that renames a file.
	 * <p>
	 * The method should be sparsely used, as most actions should provide help.
	 */
	public void markHelpUnnecessary() {
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	@Override
	public void setEnabled(boolean newValue) {
		if (isEnabled == newValue) {
			return;
		}
		isEnabled = newValue;
		firePropertyChanged(ENABLEMENT_PROPERTY, !isEnabled, isEnabled);
	}

	@Override
	public void setSupportsDefaultToolContext(boolean newValue) {
		supportsDefaultToolContext = newValue;
	}

	@Override
	public boolean supportsDefaultToolContext() {
		return supportsDefaultToolContext;
	}

	@Override
	public final JButton createButton() {
		JButton button = doCreateButton();
		button.setName(getName());
		button.setFocusable(false);
		Icon icon = toolBarData == null ? null : toolBarData.getIcon();
		if (icon == null) {
			icon = ResourceManager.getDefaultIcon();
		}

		button.setIcon(icon);
		String tt = getDescription();
		if (tt == null || tt.length() == 0) {
			tt = getName();
		}
		button.setToolTipText(tt);
		button.setEnabled(isEnabled());

		// Reverting GT-2452 because some buttons need to be able to respond to fast clicking.
		//button.setMultiClickThreshhold(500); // this prevents 2 callbacks from double-clicks

		return button;
	}

	@Override
	public JMenuItem createMenuItem(boolean isPopup) {
		JMenuItem menuItem = doCreateMenuItem();
		MenuData menuData = isPopup ? popupMenuData : menuBarData;
		if (menuData != null) {

			String text = menuData.getMenuItemName();
			String trimmed = StringUtilities.trimMiddle(text, 50);
			menuItem.setText(trimmed);
			menuItem.setIcon(menuData.getMenuIcon());
			menuItem.setMnemonic(menuData.getMnemonic());
		}
		else {
			throw new AssertException(
				"No menu data for menu type: " + (isPopup ? "Popup" : "Menubar"));
		}
		KeyStroke ks = keyBindingData == null ? null : keyBindingData.getKeyBinding();
		if (ks != null) {
			menuItem.setAccelerator(ks);
		}
		menuItem.setEnabled(isEnabled);

		return menuItem;
	}

	@Override
	public KeyBindingType getKeyBindingType() {
		return keyBindingType;
	}

	@Override
	public KeyStroke getKeyBinding() {
		return keyBindingData == null ? null : keyBindingData.getKeyBinding();
	}

	@Override
	public KeyBindingData getKeyBindingData() {
		return keyBindingData;
	}

	@Override
	public KeyBindingData getDefaultKeyBindingData() {
		return defaultKeyBindingData;
	}

	@Override
	public void setKeyBindingData(KeyBindingData newKeyBindingData) {

		if (!supportsKeyBinding(newKeyBindingData)) {
			return;
		}

		KeyBindingData oldData = keyBindingData;
		keyBindingData = KeyBindingData.validateKeyBindingData(newKeyBindingData);

		if (defaultKeyBindingData == null) {
			defaultKeyBindingData = keyBindingData;
		}

		firePropertyChanged(KEYBINDING_DATA_PROPERTY, oldData, keyBindingData);
	}

	private boolean supportsKeyBinding(KeyBindingData kbData) {

		KeyBindingType type = getKeyBindingType();
		if (type.supportsKeyBindings()) {
			return true;
		}

		KeyBindingPrecedence precedence = null;
		if (kbData != null) {
			precedence = kbData.getKeyBindingPrecedence();
		}

		if (precedence == KeyBindingPrecedence.ReservedActionsLevel) {
			return true; // reserved actions are special
		}

		// log a trace message instead of throwing an exception, as to not break any legacy code
		Msg.error(this, "Action does not support key bindings: " + getFullName(), new Throwable());
		return false;
	}

	@Override
	public void setUnvalidatedKeyBindingData(KeyBindingData newKeyBindingData) {
		KeyBindingData oldData = keyBindingData;
		keyBindingData = newKeyBindingData;
		firePropertyChanged(KEYBINDING_DATA_PROPERTY, oldData, keyBindingData);
	}

//==================================================================================================
// Non interface methods
//==================================================================================================

	/**
	 * Sets the {@link MenuData} to be used to put this action on the tool's menu bar
	 * @param newMenuData the MenuData to be used to put this action on the tool's menu bar
	 */
	public void setMenuBarData(MenuData newMenuData) {
		MenuBarData oldData = menuBarData;
		MenuBarData newDataCopy = newMenuData == null ? null : new MenuBarData(this, newMenuData);

		menuBarData = newDataCopy;
		firePropertyChanged(MENUBAR_DATA_PROPERTY, oldData, newDataCopy);
	}

	/**
	 * Sets the {@link MenuData} to be used to put this action in the tool's popup menu
	 * @param newMenuData the MenuData to be used to put this action on the tool's popup menu
	 */
	public void setPopupMenuData(MenuData newMenuData) {
		PopupMenuData oldData = popupMenuData;
		PopupMenuData newDataCopy =
			newMenuData == null ? null : new PopupMenuData(this, newMenuData);
		popupMenuData = newDataCopy;
		firePropertyChanged(POPUP_MENU_DATA_PROPERTY, oldData, newDataCopy);
	}

	/**
	 * Sets the {@link ToolBarData} to be used to put this action on the tool's toolbar
	 * @param newToolBarData the ToolBarData to be used to put this action on the tool's toolbar
	 */
	public void setToolBarData(ToolBarData newToolBarData) {

		ToolBarData oldData = toolBarData;
		ToolBarData newToolBarDataCopy = newToolBarData == null ? null
				: new ToolBarData(this, newToolBarData.getIcon(), newToolBarData.getToolBarGroup(),
					newToolBarData.getToolBarSubGroup());
		toolBarData = newToolBarDataCopy;
		firePropertyChanged(TOOLBAR_DATA_PROPERTY, oldData, newToolBarDataCopy);
	}

	/**
	 * Creates a reserved keybinding for this action. Reserved keybindings cannot be changed by
	 * the user and have a special high precedence for being process before other actions. Also,
	 * other actions are prevented from using the same KeyStroke as a reserved keybinding.
	 * @param keyStroke the keystroke to be used for the keybinding
	 */
	void createReservedKeyBinding(KeyStroke keyStroke) {
		KeyBindingData data = KeyBindingData.createReservedKeyBindingData(keyStroke);
		setKeyBindingData(data);
	}

	/**
	 * Sets the description to be used in the tooltip.
	 * @param newDescription the description to be set.
	 */
	public void setDescription(String newDescription) {
		if (SystemUtilities.isEqual(newDescription, description)) {
			return;
		}
		String oldDescription = description;
		description = newDescription;
		firePropertyChanged(DESCRIPTION_PROPERTY, oldDescription, newDescription);
	}

	/**
	 * Cleans up any resources used by the action.
	 */
	@Override
	public void dispose() {
		propertyListeners.clear();
	}

	@Override
	public String toString() {
		return getName() + "  (" + getOwner() + ")";
	}

	@Override
	public String getHelpInfo() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("   ACTION:    ").append(getOwner()).append(" - ").append(getName());
		buffer.append('\n');

		// menu path
		if (menuBarData != null) {
			buffer.append("        MENU PATH:           ")
					.append(menuBarData.getMenuPathAsString());
			buffer.append('\n');
			buffer.append("        MENU GROUP:        ").append(menuBarData.getMenuGroup());
			buffer.append('\n');

			String parentGroup = menuBarData.getParentMenuGroup();
			if (parentGroup != null) {
				buffer.append("        PARENT GROUP:         ").append(parentGroup);
				buffer.append('\n');
			}

			Icon icon = menuBarData.getMenuIcon();
			if (icon != null && icon instanceof ImageIconWrapper) {
				ImageIconWrapper wrapper = (ImageIconWrapper) icon;
				String filename = wrapper.getFilename();
				buffer.append("        MENU ICON:           ").append(filename);
				buffer.append('\n');
			}
		}

		// popup menu path
		if (popupMenuData != null) {
			buffer.append("        POPUP PATH:         ")
					.append(popupMenuData.getMenuPathAsString());
			buffer.append('\n');
			buffer.append("        POPUP GROUP:      ").append(popupMenuData.getMenuGroup());
			buffer.append('\n');

			String parentGroup = popupMenuData.getParentMenuGroup();
			if (parentGroup != null) {
				buffer.append("        PARENT GROUP:         ").append(parentGroup);
				buffer.append('\n');
			}

			String menuSubGroup = popupMenuData.getMenuSubGroup();
			if (menuSubGroup != MenuData.NO_SUBGROUP) {
				buffer.append("        POPUP SUB-GROUP:         ").append(menuSubGroup);
				buffer.append('\n');
			}

			Icon icon = popupMenuData.getMenuIcon();
			if (icon != null && icon instanceof ImageIconWrapper) {
				ImageIconWrapper wrapper = (ImageIconWrapper) icon;
				String filename = wrapper.getFilename();
				buffer.append("        POPUP ICON:         ").append(filename);
				buffer.append('\n');
			}
		}

		if (toolBarData != null) {
			buffer.append("        TOOLBAR GROUP:  ").append(toolBarData.getToolBarGroup());
			buffer.append('\n');
			Icon icon = toolBarData.getIcon();
			if (icon != null) {
				if (icon instanceof FileBasedIcon) {
					FileBasedIcon wrapper = (FileBasedIcon) icon;
					String filename = wrapper.getFilename();
					buffer.append("        TOOLBAR ICON:     ").append(filename);
					buffer.append('\n');
				}
				else if (icon instanceof ImageIcon) {
					ImageIcon ii = (ImageIcon) icon;
					String text = ii.getDescription();
					buffer.append("        TOOLBAR ICON:     ").append(text);
					buffer.append('\n');
				}
			}
		}

		KeyStroke keyStroke = getKeyBinding();
		if (keyStroke != null) {
			buffer.append("        KEYBINDING:          ").append(keyStroke.toString());
			buffer.append('\n');
		}

		String inception = getInceptionInformation();
		if (inception != null) {
			buffer.append("\n    \n");
			buffer.append("   CREATED AT: ").append(inception);
			buffer.append("\n    ");
		}
		else {
			Msg.debug(this, "No inception info");
		}

		return buffer.toString();
	}

	public void firePropertyChanged(String propertyName, Object oldValue, Object newValue) {
		if (Objects.equals(oldValue, newValue)) {
			return;
		}
		PropertyChangeEvent event = new PropertyChangeEvent(this, propertyName, oldValue, newValue);
		for (PropertyChangeListener listener : propertyListeners) {
			listener.propertyChange(event);
		}
	}

	@Override
	public Object getHelpObject() {
		return this;
	}

	/**
	 * Sets a predicate for dynamically determining the action's enabled state.  If this
	 * predicate is not set, the action's enable state must be controlled directly using the
	 * {@link DockingAction#setEnabled(boolean)} method. See 
	 * {@link DockingActionIf#isEnabledForContext(ActionContext)}
	 *  
	 * @param predicate the predicate that will be used to dynamically determine an action's 
	 * enabled state.
	 */
	public void enabledWhen(Predicate<ActionContext> predicate) {
		enabledPredicate = predicate;
	}

	/**
	 * Sets a predicate for dynamically determining if this action should be included in
	 * an impending pop-up menu.  If this predicate is not set, the action's will be included
	 * in an impending pop-up, if it is enabled. See 
	 * {@link DockingActionIf#isAddToPopup(ActionContext)}
	 *  
	 * @param predicate the predicate that will be used to dynamically determine an action's 
	 * enabled state.
	 */
	public void popupWhen(Predicate<ActionContext> predicate) {
		popupPredicate = predicate;
	}

	/**
	 * Sets a predicate for dynamically determining if this action is valid for the current 
	 * {@link ActionContext}.  See {@link DockingActionIf#isValidContext(ActionContext)}
	 *  
	 * @param predicate the predicate that will be used to dynamically determine an action's 
	 * validity for a given {@link ActionContext}
	 */
	public void validContextWhen(Predicate<ActionContext> predicate) {
		validContextPredicate = predicate;
	}

	/**
	 * Sets the ActionContext class for when this action should be added to a window
	 * <P>
	 * If this is set, the the action will only be added to windows that have providers
	 * that can produce an ActionContext that is appropriate for this action.
	 * <P>
	 * @param contextClass the ActionContext class required to be producible by a
	 * provider that is hosted in that window before this action is added to that 
	 * window. 
	 * 
	 */
	public void addToWindowWhen(Class<? extends ActionContext> contextClass) {
		addToWindowWhenContextClass = contextClass;
	}
	
	/**
	 * Tells this action to add itself to all windows
	 * <P>
	 * @param b to add to all windows or not
	 */
	public void setAddToAllWindows(boolean b) {
		shouldAddToAllWindows = b;
	}

//==================================================================================================
// Non-public methods
//==================================================================================================

	protected JButton doCreateButton() {
		return new EmptyBorderButton();
	}

	protected JMenuItem doCreateMenuItem() {
		return new DockingMenuItem();
	}

	private void recordInception() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			inceptionInformation = "";
			return;
		}
		inceptionInformation = getInceptionFromTheFirstClassThatIsNotUsOrABuilder();
	}

	protected String getInceptionFromTheFirstClassThatIsNotUsOrABuilder() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan(getClass());
		StackTraceElement[] trace =
			ReflectionUtilities.filterStackTrace(t.getStackTrace(), "ActionBuilder");
		String classInfo = trace[0].toString();
		return classInfo;
	}
	
}
