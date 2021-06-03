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
package docking.action.builder;

import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * Base class for DockingAction builders.
 * 
 * <p>Building an action requires a few steps.  One of the few required calls when using a builder
 * is {@link #onAction(Consumer)}.   This is the callback used when the action is invoked.   A
 * typical action will also complete the {@link #enabledWhen(Predicate)} method, which tells the
 * tool when an action is valid.
 * 
 * <p>To see more detailed documentation for a given method of this builder, or to understand
 * how actions are used in the tool, see the {@link DockingActionIf} 
 * interface.
 *
 * @param <T> The type of DockingAction to build
 * @param <B> the Type of action builder
 * @param <C> The type of ActionContext. By default, the ActionContext type always starts as
 * the base ActionContext class.  If the client calls the {@link #withContext(Class)} method on 
 * the builder, then that class (which must be a subclass of ActionContext) becomes the ActionContext
 * type that will be used for future calls to the builder methods that take predicates with
 * ActionContext (i.e. {@link #enabledWhen(Predicate)} and {@link #validContextWhen(Predicate)}. 
 * This works by substituting a builder with a different ActionContext type when chaining after
 * the {@link #withContext(Class)} call.
 */
public abstract class AbstractActionBuilder<T extends DockingActionIf, C extends ActionContext, B extends AbstractActionBuilder<T, C, B>> {
	private final Predicate<C> ALWAYS_TRUE = e -> true;
	/**
	 * Name for the {@code DockingAction}
	 */
	protected String name;

	/**
	 * Owner for the {@code DockingAction}
	 */
	protected String owner;

	/**
	 * Specifies the type of ActionContext that the built action works on.
	 */
	protected Class<? extends ActionContext> actionContextClass;

	/**
	 * The {@code KeyBindingType} for this {@code DockingAction}
	 */
	protected KeyBindingType keyBindingType = KeyBindingType.INDIVIDUAL;

	/**
	 * The callback to perform when the action is invoked
	 */
	protected Consumer<C> actionCallback;

	/**
	 * Description for the {@code DockingAction}.  (optional)
	 */
	private String description = "";

	/**
	 * Whether this {@code DockingAction} is enabled
	 */
	private boolean isEnabled = true;

	/**
	 * The {@code HelpLocation} for this {@code DockingAction}
	 */
	private HelpLocation helpLocation;

	/**
	 * The menu bar path.  This is the key attribute for including the action on the menu bar.
	 */
	private String[] menuPath;

	/**
	 * The menu bar menu item icon.  (optional)
	 */
	private Icon menuIcon;

	/**
	 * The menu bar menu item sub group.  (optional)
	 */
	private String menuSubGroup;

	/**
	 * The menu bar menu item group.  (optional)
	 */
	private String menuGroup;

	/**
	 * The mnemonic for the menu action (optional)
	 */
	private int menuMnemonic = MenuData.NO_MNEMONIC;
	/**
	 * The icon for the  menu item (optional)
	 */
	private Icon popupIcon;

	/**
	 * The menu path in a pop-up menu.  This is the key attribute for pop-up menu actions
	 */
	private String[] popupPath;

	/**
	 * The menu group for the item in the pop-up menu (optional)
	 */
	private String popupGroup;

	/**
	 * The menu sub group for the item in the pop-up menu (optional)
	 */
	private String popupSubGroup;

	/**
	 * The icon for the tool bar action.  This is the key attribute for actions in the toolbar.
	 */
	private Icon toolbarIcon;

	/**
	 * The group for the items on the tool bar (optional)
	 */
	private String toolBarGroup;

	/**
	 * The menu group for the item in the tool bar menu (optional)
	 */
	private String toolBarSubGroup;

	/**
	 * The key binding to assign to the action
	 */
	private KeyStroke keyBinding;

	/**
	 * Predicate for determining if an action is enabled for a given context
	 */
	private Predicate<C> enabledPredicate = null;

	/**
	 * Predicate for determining if an action should be included on the pop-up menu
	 */
	private Predicate<C> popupPredicate = ALWAYS_TRUE;

	/**
	 * Predicate for determining if an action is applicable for a given context
	 */
	private Predicate<C> validContextPredicate = ALWAYS_TRUE;

	/**
	 * Set to true if the action supports using the default tool context if the local context is invalid
	 */
	private boolean supportsDefaultToolContext;
	
	/**
	 * Specifies when the action should appear in a window.
	 */
	private When windowWhen;

	/**
	 * For use with the {@link AbstractActionBuilder#inWindow(When)} method to specify which windows (main window
	 * or secondary windows) a global tool bar or menu action will appear in.
	 *
	 */
	public enum When {
		MAIN_WINDOW, 	// action should only appear in the main window
		ALWAYS, 	    // action should appear in all windows
		CONTEXT_MATCHES // action should appear if and only if the window has
	}					// has a provider that generates the appropriate context.
	
	/**
	 * Builder constructor
	 * @param name the name of the action to be built
	 * @param owner the owner of the action to be built
	 */
	public AbstractActionBuilder(String name, String owner) {
		this.name = name;
		this.owner = owner;
		this.actionContextClass = ActionContext.class;
	}

	/**
	 * Returns this (typed for subclass) for chaining
	 * @return this for chaining
	 */
	protected abstract B self();

	/**
	 * Builds the action.  To build and install the action in one step, use 
	 * {@link #buildAndInstall(Tool)} or {@link #buildAndInstallLocal(ComponentProvider)}.
	 * {@link #inWindow(When)}
	 * @return the newly build action 
	 */
	public abstract T build();

	/**
	 * Builds and adds the action globally to the tool
	 * 
	 * @param tool the tool to add the action to
	 * @return the newly created action
	 * @see #build()
	 * @see #buildAndInstallLocal(ComponentProvider)
	 */
	public T buildAndInstall(Tool tool) {
		T action = build();
		tool.addAction(action);
		return action;
	}

	/**
	 * Builds and adds the action as a local action for the given provider
	 * 
	 * @param provider the provider to add the action to
	 * @return the newly created action
	 * @see #build()
	 * @see #buildAndInstall(Tool)
	 */
	public T buildAndInstallLocal(ComponentProvider provider) {
		T action = build();
		provider.addLocalAction(action);
		return action;
	}

	/**
	 * Configure the description for the action.  This description will appear as a tooltip
	 * over tool bar buttons.
	 * 
	 * @param text the description
	 * @return this builder (for chaining)
	 */
	public B description(String text) {
		this.description = text;
		return self();
	}

	/**
	 * Configure whether this {@code DockingAction} is enabled.
	 * 
	 * <p><b>Note: most clients do not need to use this method.  Enablement is controlled by 
	 * {@link #validContextWhen(Predicate)}.
	 * </b>
	 * 
	 * @param b {@code true} if enabled
	 * @return this builder (for chaining)
	 * @see #validContextWhen(Predicate)
	 */
	public B enabled(boolean b) {
		this.isEnabled = b;
		return self();
	}

	/**
	 * Marks this action as one that shares a key binding with other actions in the tool.  This
	 * allows multiple clients to supply actions that use the same key binding, each working
	 * within its respective action context.  See {@link KeyBindingType}.
	 * 
	 * <p>Actions are not shared by default; they are {@link KeyBindingType#INDIVIDUAL}.  This 
	 * means that each action must have its key binding assigned individually.
	 * 
	 * @return this builder (for chaining)
	 */
	public B sharedKeyBinding() {
		this.keyBindingType = KeyBindingType.SHARED;
		return self();
	}

	/**
	 * Configure {@link HelpLocation} for this {@code DockingAction}
	 * 
	 * <p>Clients are free to specify their help location directly, but many do not.  A default
	 * help location is created that uses the action name as the anchor name and the action
	 * owner as the topic.   If your anchor or topic do not follow this convention, then you 
	 * need to set help topic yourself. 
	 * 
	 * @param help the {@link HelpLocation} to configure
	 * @return this builder (for chaining)
	 */
	public B helpLocation(HelpLocation help) {
		this.helpLocation = help;
		return self();
	}

	/**
	 * Sets the menu bar path for the action.  Setting this attribute is what causes the action
	 * to appear on the tools menu bar.
	 * 
	 * @param pathElement the menu bar path for the action
	 * @return this builder (for chaining)
	 */
	public B menuPath(String... pathElement) {
		menuPath = pathElement;
		return self();
	}

	/**
	 * Sets the group for the action in the menu bar.  Actions in the same group will appear
	 * next to other actions in the same group and actions in different groups will be separated
	 * by menu dividers.
	 * 
	 * @param group for this action
	 * @return this builder (for chaining)
	 */
	public B menuGroup(String group) {
		menuGroup = group;
		return self();
	}

	/**
	 * Sets the group and sub-group for the action in the menu bar.  Actions in the same group 
	 * will appear next to other actions in the same group and actions in different groups will 
	 * be separated by menu dividers.  The sub-group is used to order the actions within the group.
	 * 
	 * @param group the group used to clump actions together
	 * @param subGroup the sub-group used to order actions within a group
	 * @return this builder (for chaining)
	 * @see #menuGroup(String)
	 */
	public B menuGroup(String group, String subGroup) {
		menuGroup = group;
		menuSubGroup = subGroup;
		return self();
	}

	/**
	 * Sets the icon to use in this action's menu bar item
	 * 
	 * @param icon the icon to use in the action's menu bar item 
	 * @return this builder (for chaining)
	 */
	public B menuIcon(Icon icon) {
		menuIcon = icon;
		return self();
	}

	/**
	 * Sets the mnemonic to use in this action's menu bar item
	 * 
	 * @param mnemonic the mnemonic to use for this action's menu bar item. 
	 * @return this builder (for chaining)
	 */
	public B menuMnemonic(int mnemonic) {
		menuMnemonic = mnemonic;
		return self();
	}

	/**
	 * Sets the pop-up menu path for the action.  Setting this attribute is what causes the action
	 * to appear on the tool's pop-up menu (assuming it is applicable for the context).
	 * 
	 * @param pathElement the menu path for the action in the pop-up menu
	 * @return this builder (for chaining)
	 * @see #popupMenuGroup(String)
	 */
	public B popupMenuPath(String... pathElement) {
		popupPath = pathElement;
		return self();
	}

	/**
	 * Sets the group for the action in the pop-up menu.  Actions in the same group will appear
	 * next to other actions in the same group and actions in different groups will be separated
	 * by menu dividers.
	 * 
	 * @param group for this action
	 * @return this builder (for chaining)
	 */
	public B popupMenuGroup(String group) {
		popupGroup = group;
		return self();
	}

	/**
	 * Sets the group and sub-group for the action in the pop-up menu.  Actions in the same group
	 * will appear next to other actions in the same group and actions in different groups will
	 * be separated by menu dividers.  The sub-group is used to order the actions within the group
	 * 
	 * @param group the group used to clump actions together
	 * @param subGroup the sub-group used to order actions within a group
	 * @return this builder (for chaining)
	 * @see #popupMenuGroup(String)
	 */
	public B popupMenuGroup(String group, String subGroup) {
		popupGroup = group;
		popupSubGroup = subGroup;
		return self();
	}

	/**
	 * Sets the icon to use in this action's pop-up menu item
	 * 
	 * @param icon the icon to use in the action's pop-up menu item 
	 * @return this builder (for chaining)
	 */
	public B popupMenuIcon(Icon icon) {
		popupIcon = icon;
		return self();
	}

	/**
	 * Sets the icon to use in this action's tool bar button.  Setting this attribute is what 
	 * causes the action to appear on the tool's or component provider's action tool bar.
	 * 
	 * @param icon the icon to use in the action's tool bar
	 * @return this builder (for chaining)
	 * @see #toolBarIcon(String)
	 */
	public B toolBarIcon(Icon icon) {
		toolbarIcon = icon;
		return self();
	}

	/**
	 * Sets the path for the icon to use in this action's tool bar button.  Setting this attribute
	 * causes the action to appear on the tool's or component provider's action tool bar.
	 * 
	 * @param iconFilepath the module-relative path for the icon to use in the action's tool bar
	 * @return this builder (for chaining)
	 * @see #toolBarIcon(Icon)
	 */
	public B toolBarIcon(String iconFilepath) {
		toolbarIcon = ResourceManager.loadImage(iconFilepath);
		return self();
	}

	/**
	 * Sets the group for the action in the tool bar.  Actions in the same group will appear
	 * next to other actions in the same group and actions in different groups will be separated
	 * by menu dividers.
	 * 
	 * <p><b>Note: you must call {@link #toolBarIcon(Icon)} or {@link #toolBarIcon(String)} for
	 * this action to appear in the toolbar.  Calling this method without the other will not 
	 * cause this action to be placed in the tool bar.
	 * </b>
	 * 
	 * @param group for this action
	 * @return this builder (for chaining)
	 * @see #toolBarGroup(String, String)
	 */
	public B toolBarGroup(String group) {
		toolBarGroup = group;
		return self();
	}

	/**
	 * Sets the group and sub-group for the action in the tool bar.  Actions in the same group
	 * will appear next to other actions in the same group and actions in different groups will
	 * be separated by menu dividers.  The sub-group is used to order the actions within the group.
	 * 
	 * <p><b>Note: you must call {@link #toolBarIcon(Icon)} or {@link #toolBarIcon(String)} for
	 * this action to appear in the toolbar.  Calling this method without the other will not 
	 * cause this action to be placed in the tool bar.
	 * </b>
	 * 
	 * @param group the group used to clump actions together.
	 * @param subGroup the sub-group used to order actions within a group.
	 * @return this builder (for chaining)
	 * @see #toolBarGroup(String)
	 */
	public B toolBarGroup(String group, String subGroup) {
		toolBarGroup = group;
		toolBarSubGroup = subGroup;
		return self();
	}

	/**
	 * Sets the key binding for this action
	 * 
	 * @param keyStroke the KeyStroke to bind to this action
	 * @return this builder (for chaining)
	 */
	public B keyBinding(KeyStroke keyStroke) {
		this.keyBinding = keyStroke;
		return self();
	}

	/**
	 * Sets the key binding for this action
	 * 
	 * @param keyStrokeString the string to parse as a KeyStroke. See
	 *  {@link KeyStroke#getKeyStroke(String)} for the format of the string.
	 * @return this builder (for chaining)
	 */
	public B keyBinding(String keyStrokeString) {
		this.keyBinding = KeyBindingUtils.parseKeyStroke(keyStrokeString);
		if (keyBinding == null && keyStrokeString != null) {
			Msg.warn(this, "Can't parse KeyStroke: " + keyStrokeString);
		}
		return self();
	}

	/**
	 * Sets the primary callback to be executed when this action is invoked.  This builder will
	 * throw an {@link IllegalStateException} if one of the build methods is called without
	 * providing this callback.
	 * 
	 * @param action the callback to execute when the action is invoked
	 * @return this builder (for chaining)
	 */
	public B onAction(Consumer<C> action) {
		actionCallback = action;
		return self();
	}

	/**
	 * Sets a predicate for dynamically determining the action's enabled state.  See 
	 * {@link DockingActionIf#isEnabledForContext(ActionContext)}
	 * 
	 * <p>If this predicate is not set, the action's enable state must be controlled 
	 * directly using the {@link DockingAction#setEnabled(boolean)} method.  We do not recommend
	 * controlling enablement directly. And, of course, if you do set this predicate, you should 
	 * not later call {@link DockingAction#setEnabled(boolean)} to manually manage enablement.
	 *  
	 * @param predicate the predicate that will be used to dynamically determine an action's 
	 *        enabled state
	 * @return this builder (for chaining)
	 */
	public B enabledWhen(Predicate<C> predicate) {
		enabledPredicate = Objects.requireNonNull(predicate);
		return self();
	}

	/**
	 * Sets a predicate for dynamically determining if this action should be included in
	 * an impending pop-up menu.  If this predicate is not set, the action will be included
	 * in an impending pop-up, if it is enabled. See 
	 * {@link DockingActionIf#isAddToPopup(ActionContext)}.
	 * 
	 * <p>Note: use this method when you wish for an action to be added to a popup menu regardless
	 * of whether it is enabled.  As mentioned above, standard popup actions will only be added
	 * to the popup when they are enabled. 
	 *  
	 * <p>Note: using this method is not sufficient to cause the action to appear in a popup 
	 * menu.  You must also use {@link #popupMenuPath(String...)}.
	 *  
	 * @param predicate the predicate that will be used to dynamically determine whether an 
	 *        action is added to a popup menu
	 * @return this builder (for chaining)
	 * @see #popupMenuPath(String...)
	 */
	public B popupWhen(Predicate<C> predicate) {
		popupPredicate = Objects.requireNonNull(predicate);
		return self();
	}

	/**
	 * Sets a predicate for dynamically determining if this action is valid for the current 
	 * {@link ActionContext}.  See {@link DockingActionIf#isValidContext(ActionContext)}.
	 * 
	 * <p>Note: most actions will not use this method, but rely instead on 
	 * {@link #enabledWhen(Predicate)}. 
	 * 
	 * <p>Note: this triggers automatic action enablement so you should not later call 
	 * {@link DockingAction#setEnabled(boolean)} to manually manage action enablement.
	 *  
	 * @param predicate the predicate that will be used to dynamically determine an action's 
	 * validity for a given {@link ActionContext}
	 * @return this builder (for chaining)
	 */
	public B validContextWhen(Predicate<C> predicate) {
		validContextPredicate = Objects.requireNonNull(predicate);

		// automatic enablement management triggered, make sure there is a existing enablement 
		// predicate. The default behavior of manual management interferes with automatic management.
		if (enabledPredicate == null) {
			enabledPredicate = ALWAYS_TRUE;
		}

		return self();
	}

	/**
	 * Sets whether the action will support using the default tool context if the focused provider's
	 * context is invalid.
	 * <P>
	 * By default, actions only work on the current focused provider's context.  Setting this
	 * to true will cause the action to be evaluated against the default tool context if the
	 * focused context is not valid for this action.
	 * 
	 * @param b the new value
	 * @return this builder (for chaining)
	 */
	public B supportsDefaultToolContext(boolean b) {
		supportsDefaultToolContext = b;
		return self();
	}
	
	/**
	 * Specifies when a global action should appear in a window (main or secondary).
	 * <P>
	 * Global menu or toolbar actions can be configured to appear in 1) only the main 
	 * window, or 2) all windows, or 3) any window that has a provider that
	 * generates an action context that matches the context that this action
	 * consumes. If the "context matches" options is chosen, then the 
	 * {@link #withContext(Class)} method must also be called to specify the matching
	 * context; otherwise an exception will be thrown when the action is built.
	 * <P>
	 *  
	 *  The default is that the action will only appear in the main window.
	 *
	 * @param when use the {@link When} enum to specify the windowing behavior
	 * of the action.
	 * 
	 * @return this builder (for chaining)
	 */
	public B inWindow(When when) {
		this.windowWhen = when;
		return self();
	}

	/**
	 * Sets the specific ActionContext type to use for the various predicate calls 
	 * ({@link #validContextWhen(Predicate)}, {@link #enabledWhen(Predicate)}, and 
	 * {@link #popupWhen(Predicate)}).
	 * <P>
	 * In other words, this allows the client to specify the type of ActionContext that is valid for
	 * the action being built.
	 * <P>
	 * To be effective, this method must be called  <b>before</b> setting any of the predicates 
	 * such as the {@link #enabledWhen(Predicate)}.  Once this method is called you can define your
	 * predicates using the more specific ActionContext and be assured your predicates will only
	 * be called when the current action context is the type (or sub-type) of the context you have
	 * specified here.
	 * <P>
	 * For example, assume you have an action that is only enabled when the context is of type
	 * FooActionContext.  If you don't call this method to set the ActionContext type,  you would have
	 * to write your predicate something like this:
	 * <pre>
	 * {@literal builder.enabledWhen(context -> }{
	 *     if (!(context instanceof FooContext)) {
	 *         return false;
	 *     }
	 *     return ((FooContext) context).isAwesome();
	 * });
	 * </pre>
	 * But by first calling the builder method <CODE>withContext(FooContext.class)</CODE>, you can 
	 * simply write:
	 *
	 * <pre>
	 * {@literal builder.enabledWhen(context -> return context.isAwesome() }}
	 * </pre>
	 *
	 * <p>Note: this triggers automatic action enablement so you should not later call 
	 * {@link DockingAction#setEnabled(boolean)} to manually manage action enablement.
	 *  
	
	 * @param newActionContextClass the more specific ActionContext type.
	 * @param <AC2> The new ActionContext type (as determined by the newActionContextClass) that
	 * the returned builder will have.
	 * @param <B2> the new builder type.
	 * @return an ActionBuilder whose generic types have been modified to match the new ActionContext.
	 * It still contains all the configuration that has been applied so far.
	 */
	@SuppressWarnings("unchecked")
	public <AC2 extends ActionContext, B2 extends AbstractActionBuilder<T, AC2, B2>> B2 withContext(
			Class<AC2> newActionContextClass) {

		if (actionContextClass != ActionContext.class) {
			throw new IllegalStateException("Can't set the ActionContext type more than once");
		}

		// automatic enablement management triggered, make sure there is a existing enablement 
		// predicate. The default behavior of manual management interferes with automatic management.
		if (enabledPredicate == null) {
			enabledPredicate = ALWAYS_TRUE;
		}

		// To make this work, we need to return a builder whose ActionContext is AC2 and not AC
		//    (which is what this builder is now)
		//
		// Since we "know" that the only thing that matters regarding the ActionContext type is that
		// the template type (AC) must match the type of actionContextClass instance variable, we
		// can get away with returning this same builder and casting it to be a builder with type 
		// AC2 instead of AC.  We can do this since we set the actionContextClass below

		actionContextClass = newActionContextClass;

		B2 newSelf = (B2) self();
		return newSelf;
	}

	protected void validate() {
		if (actionCallback == null) {
			throw new IllegalStateException(
				"Can't build a DockingAction without an action callback");
		}
		if (windowWhen == When.CONTEXT_MATCHES && actionContextClass == null) {
			throw new IllegalStateException("The InWindow state was set to "
					+ "\"CONTEXT_MATCHES\", but no context class was set. Use"
					+ " the \"withContext\" method"); 
		}
	}

	protected void decorateAction(DockingAction action) {
		action.setEnabled(isEnabled);
		action.setDescription(description);
		action.setSupportsDefaultToolContext(supportsDefaultToolContext);

		setMenuData(action);
		setToolbarData(action);
		setPopupMenuData(action);
		setKeyBindingData(action);

		if (helpLocation != null) {
			action.setHelpLocation(helpLocation);
		}

		if (enabledPredicate != null) {
			action.enabledWhen(adaptPredicate(enabledPredicate));
		}

		action.validContextWhen(adaptPredicate(validContextPredicate));
		action.popupWhen(adaptPredicate(popupPredicate));
		
		if (windowWhen == When.ALWAYS) {
			action.setAddToAllWindows(true);
		}
		else if (windowWhen == When.CONTEXT_MATCHES) {
			action.addToWindowWhen(actionContextClass);
		}
		// else action defaults to main window only
	}

	/**
	 * Since the built action will need a predicate that handles any action type, this method 
	 * creates a predicate that adapts a user supplied predicate for a more specific ActionContext
	 * to a general predicate that can accept any ActionContext.
	 * @param predicate the client supplied predicate that expects a more specific ActionContext
	 * @return a predicate that can handle any ActionContext
	 */
	@SuppressWarnings("unchecked")
	private Predicate<ActionContext> adaptPredicate(Predicate<C> predicate) {
		if (actionContextClass == ActionContext.class) {
			// don't wrap the predicate if it doesn't need it
			return (Predicate<ActionContext>) predicate;
		}
		// Convert a sub-classed ActionContext predicate to a plain ActionContext predicate
		Predicate<ActionContext> predicateAdapter = (ac) -> {
			return actionContextClass.isInstance(ac) && predicate.test((C) ac);
		};
		return predicateAdapter;
	}

	protected boolean isPopupAction() {
		return popupPath != null;
	}

	protected boolean isToolbarAction() {
		return toolbarIcon != null;
	}

	protected boolean isMenuAction() {
		return menuPath != null;
	}

	protected boolean isKeyBindingAction() {
		return keyBinding != null;
	}

	private void setPopupMenuData(DockingAction action) {
		if (isPopupAction()) {
			action.setPopupMenuData(new MenuData(popupPath, popupIcon, popupGroup,
				MenuData.NO_MNEMONIC, popupSubGroup));
		}
	}

	private void setToolbarData(DockingAction action) {
		if (isToolbarAction()) {
			action.setToolBarData(new ToolBarData(toolbarIcon, toolBarGroup, toolBarSubGroup));
		}
	}

	private void setMenuData(DockingAction action) {
		if (isMenuAction()) {
			action.setMenuBarData(
				new MenuData(menuPath, menuIcon, menuGroup, menuMnemonic, menuSubGroup));
		}
	}

	private void setKeyBindingData(DockingAction action) {
		if (isKeyBindingAction()) {
			action.setKeyBindingData(new KeyBindingData(keyBinding));
		}
	}
}
