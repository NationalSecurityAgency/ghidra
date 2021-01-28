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

import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;

import docking.action.*;
import docking.help.HelpDescriptor;
import docking.help.HelpService;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Abstract base class for creating dockable GUI components within a tool.  
 * <p>
 * The one method that must be implemented is {@link #getComponent()} which is where the top level
 * Swing JComponent is returned to be docked into the tool.  Typically, the GUI components are
 * created in the constructor along with any local actions for the provider.  The getComponent() 
 * method then simply returns the top level component previously created by this provider.
 * <p>
 * There are many other methods for configuring how to dock the component, set title information,
 * configure grouping, set the help, add actions, and receive show/hide notifications, some
 * of which are highlighted below.  Typically, implementers will use these methods to configure
 * how the GUI component behaves within the tool, and then add the business logic that uses and reacts
 * to the GUI components created in this provider.
 * <p>
 * To effectively use this class you merely need to create your component, add your actions to 
 * this class ({@link #addLocalAction(DockingActionIf)}) and then add this provider to the tool
 * ({@link #addToTool()}).
 * <p>
 * This also provides several useful convenience methods:
 * <ul>
 *  <li>{@link #addLocalAction(DockingActionIf)}
 *  <li>{@link #addToTool()}
 *  <li>{@link #setVisible(boolean)}  
 *  <li>{@link #setTitle(String)}
 *  <li>{@link #setIcon(Icon)}
 * </ul>
 * <p>
 * There are a handful of stub methods that can be overridden as desired:
 * <ul>
 *  <li>{@link #componentActivated()} and {@link #componentDeactived()}
 *  <li>{@link #componentHidden()} and {@link #componentShown()}
 * </ul>
 * 
 * <p>
 * <b><u>Show Provider Action</u></b> - Each provider has an action to show the provider.  For
 * typical, non-transient providers (see {@link #setTransient()}) the action will appear in 
 * the tool's <b>Window</b> menu.   You can have your provider also appear in the tool's toolbar
 * by calling {@link #addToTool()}.
 * <p>
 * Historical Note: This class was created so that implementors could add local actions within the constructor
 * without having to understand that they must first add themselves to the WindowManager.
 */
public abstract class ComponentProvider implements HelpDescriptor, ActionContextProvider {
	private static final String TRANSIENT_PROVIDER_TOOLBAR_WARNING_MESSAGE =
		"Transient providers are not added to the toolbar";

	private static final String TRANSIENT_PROVIDER_KEY_BINDING_WARNING_MESSAGE =
		"Transient providers cannot have key bindings";

	public static final String DEFAULT_WINDOW_GROUP = "Default";

	private static final String TOOLBAR_GROUP = "View";

	// maps for mapping old provider names and owner to new names and/or owner
	private static Map<String, String> oldOwnerMap = new HashMap<>();
	private static Map<String, String> oldNameMap = new HashMap<>();
	protected Tool dockingTool;
	private String name;
	private final String owner;
	private String title;
	private String subTitle;
	private String tabText;

	private Set<DockingActionIf> actionSet = new LinkedHashSet<>();

	/** True if this provider's action should appear in the toolbar */
	private boolean addToolbarAction;
	private boolean isTransient;
	private KeyBindingData defaultKeyBindingData;
	private Icon icon;

	private String windowMenuGroup;
	private String group = DEFAULT_WINDOW_GROUP;
	private WindowPosition defaultWindowPosition = WindowPosition.WINDOW;
	private WindowPosition defaultIntraGroupPosition = WindowPosition.STACK;
	private DockingAction showProviderAction;

	private HelpLocation helpLocation;
	private final Class<?> contextType;

	private long instanceID = UniversalIdGenerator.nextID().getValue();
	private boolean instanceIDHasBeenInitialized;

	private String inceptionInformation;

	/**
	 * Creates a new component provider with a default location of {@link WindowPosition#WINDOW}.
	 * @param tool The tool will manage and show this provider
	 * @param name The providers name.  This is used to group similar providers into a tab within
	 *        the same window.
	 * @param owner The owner of this provider, usually a plugin name.
	 */
	public ComponentProvider(Tool tool, String name, String owner) {
		this(tool, name, owner, null);
	}

	/**
	 * Creates a new component provider with a default location of {@link WindowPosition#WINDOW}.
	 * @param tool The tool that will manage and show this provider.
	 * @param name The providers name.  This is used to group similar providers into a tab within
	 *        the same window.
	 * @param owner The owner of this provider, usually a plugin name.
	 * @param contextType the type of context supported by this provider; may be null (see
	 *        {@link #getContextType()}
	 */
	public ComponentProvider(Tool tool, String name, String owner, Class<?> contextType) {
		this.dockingTool = tool;
		this.name = name;
		this.owner = owner;
		this.title = name;
		this.contextType = contextType;

		recordInception();
	}

	/**
	 * Returns the action used to show this provider
	 * @return the action
	 */
	DockingActionIf getShowProviderAction() {
		createShowProviderAction();
		return showProviderAction;
	}

	private void createShowProviderAction() {
		if (showProviderAction != null) {
			return;
		}

		if (addToolbarAction) {
			Objects.requireNonNull(icon,
				"The provider's icon cannot be null when requesting the provider's action " +
					"appear in the toolbar");
		}

		boolean supportsKeyBindings = !isTransient;
		showProviderAction = new ShowProviderAction(supportsKeyBindings);
	}

	/**
	 * Returns the component to be displayed
	 * @return the component to be displayed
	 */
	public abstract JComponent getComponent();

	/**
	 * A method that allows children to set the <code>instanceID</code> to a desired value (useful for
	 * restoring saved IDs).
	 * <p>
	 * Note: this can be called only once during the lifetime of the calling instance; otherwise, an 
	 * {@link AssertException} will be thrown.
	 * @param newID the new ID of this provider
	 */
	protected void initializeInstanceID(long newID) {
		if (instanceIDHasBeenInitialized) {
			if (newID != instanceID) {
				throw new AssertException("Cannot initialize the instanceID more than once");
			}
		}

		instanceIDHasBeenInitialized = true;
		instanceID = newID;
	}

	/**
	 * A unique ID for this provider
	 * @return unique ID for this provider
	 */
	public final long getInstanceID() {
		return instanceID;
	}

	// Default implementation
	public void requestFocus() {

		JComponent component = getComponent();
		if (component == null) {
			return; // this shouldn't happen; this implies we have been disposed
		}

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusOwner = kfm.getFocusOwner();
		if (focusOwner != null && SwingUtilities.isDescendingFrom(focusOwner, component)) {
			return;
		}

		component.requestFocus();
	}

	/**
	 * Returns true if this provider has focus
	 * 
	 * @return true if this provider has focus
	 */
	public boolean isFocusedProvider() {
		DockingWindowManager dwm = DockingWindowManager.getInstance(getComponent());
		if (dwm == null) {
			return false; // can happen in testing
		}
		ComponentPlaceholder placeholder = dwm.getFocusedComponent();
		return placeholder != null && placeholder.getProvider() == this;
	}

	/**
	 * Adds this provider to the tool in a new window that is not initially visible.  The provider
	 * will then show up in the "Windows" menu of the tool
	 */
	public void addToTool() {
		if (isInTool()) {
			throw new IllegalStateException("Component already added: " + name);
		}
		dockingTool.addComponentProvider(this, false);
		for (DockingActionIf action : actionSet) {
			dockingTool.addLocalAction(this, action);
		}
		if (subTitle != null) {
			setSubTitle(subTitle);
		}
	}

	/**
	 * Removes this provider from the tool.
	 */
	public void removeFromTool() {
		dockingTool.removeAction(showProviderAction);
		dockingTool.removeComponentProvider(this);
	}

	/**
	 * Adds the given action to the system and associates it with this provider.
	 * @param action The action to add.
	 */
	public void addLocalAction(DockingActionIf action) {
		if (actionSet.contains(action)) {
			return;
		}
		actionSet.add(action);
		if (isInTool()) {
			dockingTool.addLocalAction(this, action);
		}
	}

	/**
	 * Removes the given action from this component provider.
	 * @param action The action to remove.
	 */
	protected void removeLocalAction(DockingAction action) {
		actionSet.remove(action);
		if (isInTool()) {
			dockingTool.removeLocalAction(this, action);
		}
	}

	/**
	 * Removes all local actions from this component provider
	 */
	protected void removeAllLocalActions() {
		if (isInTool()) {
			actionSet.forEach(action -> dockingTool.removeLocalAction(this, action));
		}
		actionSet.clear();
	}

	/**
	 * Convenience method to show or hide this provider.
	 * @param visible True shows the provider; false hides the provider
	 */
	public void setVisible(boolean visible) {
		if (visible && !isInTool()) {
			addToTool();
		}
		dockingTool.showComponentProvider(this, visible);
	}

	public void toFront() {
		dockingTool.toFront(this);
	}

	public boolean isInTool() {
		if (dockingTool == null) {
			return false;
		}
		DockingWindowManager manager = dockingTool.getWindowManager();
		if (manager == null) {
			return false;
		}
		return manager.containsProvider(this);
	}

	/**
	 * A signal used when installing actions.  Some actions are only added to a given window 
	 * if there is a provider in that window that can work with that action.  Providers can return
	 * a context class from this method to control whether dependent actions get added.  Most
	 * providers return null for this method, which means they will not have any dependent 
	 * actions added to windows other than the primary application window.
	 * 
	 * @return a class representing the desired context type or null;
	 */
	public Class<?> getContextType() {
		return contextType;
	}

	/**
	 * Convenience method to indicate if this provider is showing.
	 * @return true if this provider is showing.
	 */
	public boolean isVisible() {
		return dockingTool.isVisible(this);
	}

	/**
	 * Convenience method to indicate if this provider is the active provider (has focus)
	 * @return true if this provider is active.
	 */
	public boolean isActive() {
		return dockingTool.isActive(this);
	}

	/**
	 * This is the callback that will happen when the user presses the 'X' button of a provider.
	 * Transient providers will be removed from the tool completely.   Non-transient providers
	 * will merely be hidden.
	 * 
	 * <P>Subclasses may override this method to prevent a provider from being closed; for 
	 * example, if an editor has unsaved changes, then this method could prevent the close from
	 * happening.
	 */
	public void closeComponent() {
		if (isTransient) {
			removeFromTool();
		}
		else {
			setVisible(false);
		}
	}

	/**
	 * Notifies the component provider that it is now the active provider
	 */
	public void componentActivated() {
		// subclasses implement as needed
	}

	/**
	 * Notifies the component provider that it is no longer the active provider
	 */
	public void componentDeactived() {
		// subclasses implement as needed
	}

	/**
	 * Notifies the provider that the component is being hidden.  This happens when the 
	 * provider is being closed.
	 */
	public void componentHidden() {
		// subclasses implement as needed
	}

	/**
	 * Notifies the provider that the component is being shown.
	 */
	public void componentShown() {
		// subclasses implement as needed
	}

	/**
	 * Returns the context object which corresponds to the
	 * area of focus within this provider's component.  Null
	 * is returned when there is no context.
	 * @param event popup event which corresponds to this request.
	 * May be null for key-stroke or other non-mouse event.
	 */
	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Component c = getComponent();
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusedComponent = kfm.getFocusOwner();
		if (focusedComponent != null && SwingUtilities.isDescendingFrom(focusedComponent, c)) {
			c = focusedComponent;
		}
		return createContext(c, null);
	}

	/**
	 * A default method for creating an action context for this provider
	 * @return the new context
	 */
	protected ActionContext createContext() {
		return new ActionContext(this);
	}

	/**
	 * A default method for creating an action context for this provider, using the given
	 * {@link ActionContext#getContextObject() context object}
	 * 
	 * @param contextObject the provider-specific context object
	 * @return the new context
	 */
	protected ActionContext createContext(Object contextObject) {
		return new ActionContext(this).setContextObject(contextObject);
	}

	/**
	 * A default method for creating an action context for this provider, using the given
	 * {@link ActionContext#getContextObject() context object} and component
	 * 
	 * @param sourceComponent the component that is the target of the context being created
	 * @param contextObject the provider-specific context object
	 * @return the new context
	 */
	protected ActionContext createContext(Component sourceComponent, Object contextObject) {
		return new ActionContext(this, sourceComponent).setContextObject(contextObject);
	}

	/**
	 * Kicks the tool to let it know the context for this provider has changed.
	 */
	public void contextChanged() {
		dockingTool.contextChanged(this);
	}

	/**
	 * Returns the general HelpLocation for this provider.  Should return null only if no 
	 * help documentation exists.
	 * 
	 * @return the help location 
	 */
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	public void setHelpLocation(HelpLocation helpLocation) {
		this.helpLocation = helpLocation;
		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(this, helpLocation);

		if (showProviderAction != null) {
			showProviderAction.setHelpLocation(helpLocation);
		}
	}

	/**
	 * Returns the Icon associated with the component view
	 * @return the Icon associated with the component view
	 */
	public Icon getIcon() {
		return icon;
	}

	/**
	 * Returns the name of this provider
	 * @return the name of this provider
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the owner of this provider (usually a plugin)
	 * @return the owner of this provider
	 */
	public String getOwner() {
		return owner;
	}

	/**
	 * Sets the provider's title.
	 * @param title the title string to use.
	 */
	public void setTitle(String title) {
		this.title = title;
		if (isInTool()) {
			dockingTool.updateTitle(this);
		}
	}

	/**
	 * Sets the provider's sub-title (Sub-titles don't show up
	 * in the window menu).
	 * @param subTitle the sub-title string to use.
	 */
	public void setSubTitle(String subTitle) {
		this.subTitle = subTitle;
		if (isInTool()) {
			dockingTool.updateTitle(this);
		}
	}

	/**
	 * Sets the text to be displayed on tabs when provider is stacked with other providers.
	 * @param tabText the tab text.
	 */
	public void setTabText(String tabText) {
		this.tabText = tabText;
	}

	/**
	 * Returns the provider's current title.
	 * @return the provider's current title.
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * Returns the provider's current sub-title (Sub-titles don't show up
	 * in the window menu).
	 * @return the provider's current sub-title.
	 */

	public String getSubTitle() {
		return subTitle;
	}

	/**
	 * Returns the optionally set text to display in the tab for a component provider.   The
	 * text returned from {@link #getTitle()} will be used by default.
	 * 
	 * @return the optionally set text to display in the tab for a component provider.
	 * @see #setTabText(String)
	 */

	public String getTabText() {
		return tabText;
	}

	/**
	 * Sets the default key binding that will show this provider when pressed.   This value can
	 * be changed by the user and saved as part of the Tool options.
	 * 
	 * @param kbData the key binding
	 */
	protected void setKeyBinding(KeyBindingData kbData) {

		if (isInTool()) {
			throw new IllegalStateException(
				"Cannot set the default key binding after the provider is added to the tool");
		}

		this.defaultKeyBindingData = kbData;

		if (isTransient && kbData != null) {
			Msg.error(this, TRANSIENT_PROVIDER_KEY_BINDING_WARNING_MESSAGE,
				ReflectionUtilities.createJavaFilteredThrowable());
			this.defaultKeyBindingData = null;
		}
	}

	/**
	 * Convenience method for setting the provider's icon
	 * @param icon the icon to use for this provider
	 */
	protected void setIcon(Icon icon) {
		this.icon = icon;
		if (!isInTool()) {
			return;
		}

		if (addToolbarAction && showProviderAction != null) {
			Objects.requireNonNull(icon, "Icon cannot be set to null when using a toolbar action");
			showProviderAction.setToolBarData(new ToolBarData(icon));
		}

		dockingTool.getWindowManager().setIcon(this, icon);
	}

	/**
	 * Signals that this provider's action for showing the provider should appear in the main 
	 * toolbar
	 */
	protected void addToToolbar() {
		this.addToolbarAction = true;

		if (isTransient) {
			Msg.error(this, TRANSIENT_PROVIDER_TOOLBAR_WARNING_MESSAGE,
				ReflectionUtilities.createJavaFilteredThrowable());
			addToolbarAction = false;
		}
	}

	/**
	 * Returns the name of a cascading sub-menu name to use when when showing this provider in the
	 * "Window" menu. If the group name is null, the item will appear in the top-level menu.
	 * @return the menu group for this provider or null if this provider should appear in the
	 * top-level menu.
	 */
	public String getWindowSubMenuName() {
		return windowMenuGroup;
	}

	/**
	 * Returns true if this component goes away during a user session (most providers remain in
	 * the tool all session long, visible or not)
	 * @return true if transient
	 */
	public boolean isTransient() {
		return isTransient || isSnapshot();
	}

	/**
	 * A special marker that indicates this provider is a snapshot of a primary provider, 
	 * somewhat like a picture of the primary provider.
	 * 
	 * @return true if a snapshot
	 */
	public boolean isSnapshot() {
		return false;
	}

	/**
	 * Sets this class to be transient.  Setting this provider to be transient will cause
	 * this provider to be removed from the tool when the corresponding window is closed.
	 */
	protected void setTransient() {
		isTransient = true;

		if (isInTool()) {
			throw new IllegalStateException(
				"A component provider cannot be marked as 'transient' " +
					"after it is added to the tool");
		}

		// avoid visually disturbing the user by adding/removing toolbar actions for temp providers
		if (addToolbarAction) {
			addToolbarAction = false;
			Msg.error(this, TRANSIENT_PROVIDER_TOOLBAR_WARNING_MESSAGE,
				ReflectionUtilities.createJavaFilteredThrowable());
		}

		if (defaultKeyBindingData != null) {
			defaultKeyBindingData = null;
			Msg.error(this, TRANSIENT_PROVIDER_KEY_BINDING_WARNING_MESSAGE,
				ReflectionUtilities.createJavaFilteredThrowable());
		}
	}

	/**
	 * Sets the window menu group.  If the window menu group is null, the corresponding window menu
	 * item will appear in the root menu, otherwise it will appear in a 
	 * sub-menu named <code>group</code>.
	 * 
	 * @param group the name of the window's sub-menu for this provider
	 */
	protected void setWindowMenuGroup(String group) {
		this.windowMenuGroup = group;
	}

	/**
	 * The initial {@link WindowPosition} of this provider.  If a {@link #getWindowGroup() window
	 * group} is provided, then this position is relative to that provider.  Otherwise, this 
	 * position is relative to the tool window.
	 * 
	 * @return The initial {@link WindowPosition} of this provider. 
	 */
	public WindowPosition getDefaultWindowPosition() {
		return defaultWindowPosition;
	}

	/**
	 * Sets the default position of this provider when being shown for the first time.  If the
	 * providers position in the tool has been saved before, then this value is ignored.
	 * 
	 * @param windowPosition the position 
	 * @see #getDefaultWindowPosition()
	 */
	protected void setDefaultWindowPosition(WindowPosition windowPosition) {
		defaultWindowPosition = windowPosition;
	}

	/**
	 * The position of this provider when being placed with other members of the same group.  As
	 * an example, assume this provider is being shown for the first time while there is another
	 * member of its {@link #getWindowGroup() window group} already visible.  Further, assume 
	 * that this method will return {@link WindowPosition#STACK}.  This provider will then be
	 * stacked upon the already showing provider.
	 * <p>
	 * To determine where this provider should be initially shown, 
	 * see {@link #getDefaultWindowPosition()}.
	 * 
	 * @return The position of this provider when being placed with other members of the same group.
	 */
	public WindowPosition getIntraGroupPosition() {
		return defaultIntraGroupPosition;
	}

	/**
	 * See {@link #getIntraGroupPosition()}.
	 * 
	 * @param position the new position
	 */
	public void setIntraGroupPosition(WindowPosition position) {
		this.defaultIntraGroupPosition = position;
	}

	/**
	 * Returns an optional group designator that, if non-null, the docking window manager uses to 
	 * determine the initial location of the new component relative to any existing instances
	 * of this component Provider.  
	 * <p>
	 * The docking window manager will use {@link #getIntraGroupPosition() Intra-group Position}  
	 * to decide where to place this provider inside of the already open instances of the 
	 * same group.  The default position is 'stack', which results in the new instance being
	 * stacked with other instances of this provider that have the same group unless that instance is
	 * the active provider or is currently stacked with the active provider. (This is to prevent
	 * new windows from covering the active window).
	 * 
	 * @return the window group 
	 */
	public String getWindowGroup() {
		return group;
	}

	/**
	 * Sets the window group.  See {@link #getWindowGroup()}.
	 * 
	 * @param group the group for this provider.
	 */
	protected void setWindowGroup(String group) {
		this.group = group;
	}

	@Override
	public String getHelpInfo() {
		return "   PROVIDER: " + getName() + "\n";
	}

	@Override
	public Object getHelpObject() {
		return this;
	}

	public Tool getTool() {
		return dockingTool;
	}

	@Override
	public String toString() {
		return name + " - " + getTitle() + " - " + getSubTitle();
	}

	private void recordInception() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			inceptionInformation = "";
			return;
		}

		inceptionInformation = getInceptionFromTheFirstClassThatIsNotUs();
	}

	private String getInceptionFromTheFirstClassThatIsNotUs() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan(getClass());
		StackTraceElement[] trace = t.getStackTrace();
		String classInfo = trace[0].toString();
		return classInfo;
	}

	/**
	 * Returns any registered new provider name for the oldName/oldOwner pair.
	 * @param oldOwner the old owner name
	 * @param oldName the old provider name
	 * @return the new provider name for that oldOwner/oldName
	 */
	public static String getMappedOwner(String oldOwner, String oldName) {
		String key = getKey(oldOwner, oldName);
		return oldOwnerMap.get(key);
	}

	/**
	 * Returns any registered new provider owner for the oldName/oldOwner pair.
	 * @param oldOwner the old owner name
	 * @param oldName the old provider name
	 * @return the new provider owner for that oldOwner/oldName
	 */
	public static String getMappedName(String oldOwner, String oldName) {
		String key = getKey(oldOwner, oldName);
		return oldNameMap.get(key);
	}

	/**
	 * Register a name and/or owner change to a provider so that old tools can restore those 
	 * provider windows to their old position and size. Note you must supply all four 
	 * arguments. If the name or owner did not change, use the name or owner that did not change 
	 * for both the old and new values.
	 * 
	 * <p>Note: when you make use of this method, please signal when it is safe to remove 
	 * its usage.
	 * 
	 * @param oldName the old name of the provider.
	 * @param oldOwner the old owner of the provider.
	 * @param newName the new name of the provider. If the name did not change, use the old name here.
	 * @param newOwner the new owner of the provider. If the owner did not change, use the old owner here.
	 */
	public static void registerProviderNameOwnerChange(String oldName, String oldOwner,
			String newName, String newOwner) {
		String key = getKey(oldOwner, oldName);
		oldOwnerMap.put(key, newOwner);
		oldNameMap.put(key, newName);
	}

	private static String getKey(String oldOwner, String oldName) {
		return "owner=" + oldOwner + "name=" + oldName;
	}

	private class ShowProviderAction extends DockingAction {

		ShowProviderAction(boolean supportsKeyBindings) {
			super(name, owner,
				supportsKeyBindings ? KeyBindingType.SHARED : KeyBindingType.UNSUPPORTED);

			if (addToolbarAction) {
				setToolBarData(new ToolBarData(icon, TOOLBAR_GROUP));
			}

			if (supportsKeyBindings && defaultKeyBindingData != null) {
				// this action itself is not 'key binding managed', but the system *will* use
				// any key binding value we set when connecting 'shared' actions
				setKeyBindingData(defaultKeyBindingData);
			}

			setDescription("Display " + name);
			HelpLocation providerHelp = ComponentProvider.this.getHelpLocation();
			if (providerHelp != null) {
				setHelpLocation(providerHelp);
			}
		}

		@Override
		public void actionPerformed(ActionContext context) {

			DockingWindowManager myDwm = DockingWindowManager.getInstance(getComponent());
			if (myDwm == null) {
				// this can happen when the tool loses focus
				dockingTool.showComponentProvider(ComponentProvider.this, true);
				return;
			}

			myDwm.showComponent(ComponentProvider.this, true, true);
		}

		@Override
		protected String getInceptionFromTheFirstClassThatIsNotUsOrABuilder() {
			return inceptionInformation;
		}
	}
}
