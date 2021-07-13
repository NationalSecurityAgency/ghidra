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
package docking.actions;

import static org.apache.commons.lang3.StringUtils.*;

import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import docking.DockingUtils;
import docking.Tool;
import docking.action.*;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import util.CollectionUtils;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A class to provide utilities for system key bindings, such as importing and
 * exporting key binding configurations.
 * 
 * 
 * @since Tracker Id 329
 */
public class KeyBindingUtils {
	private static final String LAST_KEY_BINDING_EXPORT_DIRECTORY = "LastKeyBindingExportDirectory";

	private static final String RELEASED = "released";
	private static final String TYPED = "typed";
	private static final String PRESSED = "pressed";

	private static final String SHIFT = "Shift";
	private static final String CTRL = "Ctrl";
	private static final String CONTROL = "Control";
	private static final String ALT = "Alt";
	private static final String META = "Meta";
	private static final String MODIFIER_SEPARATOR = "-";

	private static final Logger log = LogManager.getLogger(KeyBindingUtils.class);

	public static final String PREFERENCES_FILE_EXTENSION = ".kbxml";
	private static final GhidraFileFilter FILE_FILTER = new GhidraFileFilter() {
		@Override
		public boolean accept(File pathname, GhidraFileChooserModel model) {
			return (pathname.isDirectory()) ||
				(pathname.getName().endsWith(PREFERENCES_FILE_EXTENSION));
		}

		@Override
		public String getDescription() {
			return "Key Bindings XML Files";
		}
	};

	private KeyBindingUtils() {
		// util class
	}

	public static ToolOptions importKeyBindings() {
		// show a filechooser for the user to choose a location
		InputStream inputStream = getInputStreamForFile(getStartingDir());
		return createOptionsforKeybindings(inputStream);
	}

	/**
	 * Imports key bindings from a location selected by the user.
	 * <p>
	 * If there is a problem reading the data then the user will be shown an
	 * error dialog.
	 * 
	 * @param inputStream the input stream from which to read options
	 * @return An options object that is composed of key binding names and their
	 *         associated keystrokes.
	 */
	public static ToolOptions createOptionsforKeybindings(InputStream inputStream) {
		if (inputStream == null) {
			return null;
		}

		ToolOptions newKeyBindingOptions = null;

		SAXBuilder builder = XmlUtilities.createSecureSAXBuilder(false, false);
		Element rootElement = null;
		try {
			rootElement = builder.build(inputStream).getRootElement();
		}
		catch (JDOMException e) {
			Msg.showError(log, null, "Error Loading Key Bindings", "Unable to build XML data.", e);
		}
		catch (IOException e) {
			Msg.showError(log, null, "Error Loading Key Bindings", "Unable to build XML data.", e);
		}
		if (rootElement != null) {
			newKeyBindingOptions = new ToolOptions(rootElement);
		}
		try {
			inputStream.close();
		}
		catch (IOException ioe) {
			// we tried
		}
		return newKeyBindingOptions;
	}

	/**
	 * Saves the key bindings from the provided options object to a file chosen
	 * by the user.
	 * <p>
	 * If there is a problem writing the data then the user will be shown an
	 * error dialog.
	 * 
	 * @param keyBindingOptions The options that contains key binding data.
	 */
	public static void exportKeyBindings(ToolOptions keyBindingOptions) {
		// show a filechooser for the user to choose a location
		OutputStream outputStream = getOutputStreamForFile(getStartingDir());

		if (outputStream == null) {
			return;
		}

		// create the xml structure, the outputter and then write the data
		Element rootElement = keyBindingOptions.getXmlRoot(true);
		Document document = new Document(rootElement);
		XMLOutputter xmlOutputter = new GenericXMLOutputter();

		try {
			xmlOutputter.output(document, outputStream);
		}
		catch (IOException ioe) {
			Msg.showError(log, null, "Error Saving Key Bindings",
				"Unable to save key bindings as XML data.", ioe);
		}

		try {
			outputStream.close();
		}
		catch (IOException ioe) {
			// we tried
		}
	}

	/**
	 * Changes the given key event to the new source component and then dispatches that event.
	 * This method is intended for clients that wish to effectively take a key event given to
	 * one component and give it to another component.
	 * 
	 * <p>This method exists to deal with the complicated nature of key event processing and
	 * how our (not Java's) framework processes key event bindings to trigger actions.  If not
	 * for our special processing of action key bindings, then this method would not be
	 * necessary.
	 * 
	 * <p><b>This is seldom-used code; if you don't know when to use this code, then don't.</b>
	 * 
	 * @param newSource the new target of the event
	 * @param e the existing event
	 */
	public static void retargetEvent(Component newSource, KeyEvent e) {

		if (e.getSource() == newSource) {
			return; // yes '=='; prevent recursion 
		}

		KeyEvent newEvent = new KeyEvent(newSource, e.getID(), e.getWhen(), e.getModifiersEx(),
			e.getKeyCode(), e.getKeyChar(), e.getKeyLocation());

		/*
		 						Unusual Code Alert!
		 						
			The KeyboardFocusManager is a complicated beast.  Here we use knowledge of one such
			complication to correctly route key events.  If the client of this method passes
			a component whose 'isShowing()' returns false, then the manager will not send the
			event to that component.   Almost all clients will pass fully attached/realized
			components to the manager.   We, however, will sometimes pass components that are not
			attached; for example, when we are using said components with a renderer to perform
			our own painting.   In the case of non-attached components, we must call the
			redispatchEvent() method ourselves.
			
			Why don't we just always call redispatchEvent()?  Well, that
			method will not pass the new cloned event we just created back through the full
			key event pipeline.  This means that tool-level (our Tool API, not Java)
			actions will not work, as tool-level actions are handled at the beginning of the
			key event pipeline, not by the components themselves.
			
			Also, we have here guilty knowledge that the aforementioned tool-level key processing
			will check to see if the event was consumed.  If consumed, then no further processing
			will happen; if not consumed, then the framework will continue to process the event
			passed into this method.   Thus, after we send the new event, we will update the
			original event to match the consumed state of our new event.  This means that the
			component passed to this method must, somewhere in its processing, consume the key
			event we dispatch here, if they do not wish for any further processing to take place.
		 */
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		if (newSource.isShowing()) {
			kfm.dispatchEvent(newEvent);
		}
		else {
			kfm.redispatchEvent(newSource, newEvent);
		}

		if (newEvent.isConsumed()) {
			e.consume();
		}
	}

	/**
	 * A convenience method to register the given action with the given
	 * component. This is not usually done, as the action system is usually
	 * managed by the application's tool. However, for actions that are not
	 * registered with a tool, they can instead be bound to a component, hence
	 * this method.
	 * <p>
	 * The given action must have a keystroke assigned, or this method will do
	 * nothing.
	 * 
	 * @param component the component to which the given action will be bound
	 * @param action the action to bind
	 */
	public static void registerAction(JComponent component, DockingAction action) {
		KeyStroke keyBinding = action.getKeyBinding();
		registerAction(component, keyBinding, new ActionAdapter(action), JComponent.WHEN_FOCUSED);
	}

	/**
	 * A convenience method to register the given action with the given
	 * component. This is not usually done, as the action system is usually
	 * managed by the application's tool. However, for actions that are not
	 * registered with a tool, they can instead be bound to a component, hence
	 * this method.
	 * <p>
	 * The given action must have a keystroke assigned, or this method will do
	 * nothing.
	 * 
	 * <p>
	 * A typical use-case is to register an existing docking action with a text
	 * component, which is needed because the docking key event processing will
	 * not execute docking- registered actions if a text component has focus.
	 * 
	 * @param component the component to which the given action will be bound
	 * @param action the action to bind
	 * @param contextProvider the provider of the context
	 */
	public static void registerAction(JComponent component, DockingAction action,
			ActionContextProvider contextProvider) {
		KeyStroke keyBinding = action.getKeyBinding();
		registerAction(component, keyBinding, new ActionAdapter(action, contextProvider),
			JComponent.WHEN_FOCUSED);
	}

	/**
	 * A convenience method to register the given action with the given
	 * component. This is not usually done, as the action system is usually
	 * managed by the application's tool. However, for actions that are not
	 * registered with a tool, they can instead be bound to a component, hence
	 * this method.
	 * <p>
	 * The given action must have a keystroke assigned, or this method will do
	 * nothing.
	 * 
	 * <p>
	 * A typical use-case is to register an existing docking action with a text
	 * component, which is needed because the docking key event processing will
	 * not execute docking- registered actions if a text component has focus.
	 * 
	 * @param component the component to which the given action will be bound
	 * @param action the action to bind
	 * @param contextProvider the provider of the context
	 * @param focusCondition see {@link JComponent} for more info; the default
	 *            is usually {@link JComponent#WHEN_FOCUSED}
	 */
	public static void registerAction(JComponent component, DockingAction action,
			ActionContextProvider contextProvider, int focusCondition) {
		KeyStroke keyBinding = action.getKeyBinding();
		registerAction(component, keyBinding, new ActionAdapter(action, contextProvider),
			focusCondition);
	}

	/**
	 * Registers the given action with the given key binding on the given
	 * component.
	 * 
	 * @param component the component to which the action will be registered
	 * @param keyStroke the keystroke for to which the action will be bound
	 * @param action the action to execute when the given keystroke is triggered
	 * @param focusCondition the focus condition under which to bind the action
	 *            ({@link JComponent#getInputMap(int)}).  See {@link JComponent} for more info;
	 *            the default is usually {@link JComponent#WHEN_FOCUSED}
	 */
	public static void registerAction(JComponent component, KeyStroke keyStroke, Action action,
			int focusCondition) {
		if (keyStroke == null) {
			Msg.debug(KeyBindingUtils.class, "Attempted to register an action without " +
				"providing a keystroke - action: " + action.getValue(Action.NAME));
			return;
		}

		InputMap im = component.getInputMap(focusCondition);
		if (im == null) {
			return;
		}

		ActionMap am = component.getActionMap();
		if (am == null) {
			return;
		}

		Object keyText = im.get(keyStroke);
		if (keyText == null) {
			// no binding--just pick a name
			keyText = action.getValue(Action.NAME);
			im.put(keyStroke, keyText);
		}

		am.put(keyText, action);
	}

	/**
	 * Allows the client to clear Java key bindings when the client is creating a docking
	 * action.   Without this call, any actions bound to the given component will prevent an
	 * action with the same key binding from firing.  This is useful when your
	 * application is using tool-level key bindings that share the same
	 * keystroke as a built-in Java action, such as Ctrl-C for the copy action.
	 * 
	 * @param component the component for which to clear the key binding
	 * @param action the action from which to get the key binding
	 */
	public static void clearKeyBinding(JComponent component, DockingActionIf action) {
		KeyStroke keyBinding = action.getKeyBinding();
		if (keyBinding == null) {
			return;
		}
		clearKeyBinding(component, keyBinding);
	}

	/**
	 * Allows clients to clear Java key bindings. This is useful when your
	 * application is using tool-level key bindings that share the same
	 * keystroke as a built-in Java action, such as Ctrl-C for the copy action.
	 * <p>
	 * Note: this method clears the key binding for the
	 * {@link JComponent#WHEN_FOCUSED} and
	 * {@link JComponent#WHEN_ANCESTOR_OF_FOCUSED_COMPONENT} focus conditions.
	 * 
	 * @param component the component for which to clear the key binding
	 * @param keyStroke the keystroke of the binding to be cleared
	 * @see #clearKeyBinding(JComponent, KeyStroke, int)
	 */
	public static void clearKeyBinding(JComponent component, KeyStroke keyStroke) {
		clearKeyBinding(component, keyStroke, JComponent.WHEN_FOCUSED);
		clearKeyBinding(component, keyStroke, JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
	}

	/**
	 * Allows clients to clear Java key bindings. This is useful when your
	 * application is using tool-level key bindings that share the same
	 * keystroke as a built-in Java action, such as Ctrl-C for the copy action.
	 * 
	 * @param component the component for which to clear the key binding
	 * @param keyStroke the keystroke of the binding to be cleared
	 * @param focusCondition the particular focus condition under which the
	 *            given keystroke is used (see
	 *            {@link JComponent#getInputMap(int)}).
	 */
	public static void clearKeyBinding(JComponent component, KeyStroke keyStroke,
			int focusCondition) {
		InputMap inputMap = component.getInputMap(focusCondition);
		if (inputMap != null) {
			inputMap.put(keyStroke, "none");
		}
	}

	/**
	 * Clears the currently assigned Java key binding for the action by the given name.  This
	 * method will find the currently assigned key binding, if any, and then remove it.
	 * 
	 * @param component the component for which to clear the key binding
	 * @param actionName the name of the action that should not have a key binding
	 * @see LookAndFeel
	 */
	public static void clearKeyBinding(JComponent component, String actionName) {

		InputMap inputMap = component.getInputMap(JComponent.WHEN_FOCUSED);
		if (inputMap == null) {
			return;
		}

		KeyStroke keyStroke = null;
		KeyStroke[] keys = inputMap.allKeys();
		for (KeyStroke ks : keys) {
			Object object = inputMap.get(ks);
			if (actionName.equals(object)) {
				keyStroke = ks;
				break;
			}
		}

		if (keyStroke != null) {
			clearKeyBinding(component, keyStroke);
		}
	}

	/**
	 * Returns the registered action for the given keystroke, or null of no
	 * action is bound to that keystroke.
	 * 
	 * @param component the component for which to check the binding
	 * @param keyStroke the keystroke for which to find a bound action
	 * @param focusCondition the focus condition under which to check for the
	 *            binding ({@link JComponent#getInputMap(int)})
	 * @return the action registered to the given keystroke, or null of no
	 *         action is registered
	 */
	public static Action getAction(JComponent component, KeyStroke keyStroke, int focusCondition) {
		InputMap inputMap = component.getInputMap(focusCondition);
		ActionMap actionMap = component.getActionMap();
		if (inputMap == null || actionMap == null) {
			return null;
		}

		Object binding = inputMap.get(keyStroke);
		return (binding == null) ? null : actionMap.get(binding);
	}

	/**
	 * A utility method to get all key binding actions.  This method will
	 * only return actions that support {@link KeyBindingType key bindings}.
	 * 
	 * <p>The mapping returned provides a list of items because it is possible for there to
	 * exists multiple actions with the same name and owner.  (This can happen when multiple copies
	 * of a component provider are shown, each with their own set of actions that share the
	 * same name.)
	 * 
	 * @param tool the tool containing the actions
	 * @return the actions mapped by their full name (e.g., 'Name (OwnerName)')
	 */
	public static Map<String, List<DockingActionIf>> getAllActionsByFullName(Tool tool) {

		Map<String, List<DockingActionIf>> result =
			LazyMap.lazyMap(new HashMap<>(), s -> new LinkedList<>());
		Set<DockingActionIf> actions = tool.getAllActions();
		for (DockingActionIf action : actions) {
			if (isIgnored(action)) {
				// don't bother tracking non-keybinding actions; this would be a mistake due
				// to the potential for a shared key binding action overwriting its
				// SharedStubKeyBindingAction
				continue;
			}

			result.get(action.getFullName()).add(action);
		}

		return result;
	}

	/**
	 * A utility method to get all key binding actions that have the given owner.
	 * This method will remove duplicate actions and will only return actions
	 * that support {@link KeyBindingType key bindings}.
	 * 
	 * @param tool the tool containing the actions
	 * @param owner the action owner name
	 * @return the actions
	 */
	public static Set<DockingActionIf> getKeyBindingActionsForOwner(Tool tool,
			String owner) {

		Map<String, DockingActionIf> deduper = new HashMap<>();
		Set<DockingActionIf> actions = tool.getDockingActionsByOwnerName(owner);
		for (DockingActionIf action : actions) {
			if (isIgnored(action)) {
				// don't bother tracking non-keybinding actions; this would be a mistake due
				// to the potential for a shared key binding action overwriting its
				// SharedStubKeyBindingAction
				continue;
			}

			deduper.put(action.getFullName(), action);
		}

		return CollectionUtils.asSet(deduper.values());
	}

	/**
	 * Returns all actions that match the given owner and name
	 * 
	 * @param allActions the universe of actions
	 * @param owner the owner
	 * @param name the name
	 * @return the actions
	 */
	public static Set<DockingActionIf> getActions(Set<DockingActionIf> allActions, String owner,
			String name) {
		return allActions.stream()
				.filter(a -> a.getOwner().equals(owner))
				.filter(a -> a.getName().equals(name))
				.collect(Collectors.toSet());
	}

	/**
	 * Takes the existing docking action and allows it to be registered with
	 * Swing components
	 * 
	 * <p>
	 * The new action will not be correctly wired into the Docking Action
	 * Context system. This means that the given docking action should not rely
	 * on {@link DockingAction#isEnabledForContext(docking.ActionContext)} to
	 * work when called from the Swing widget.
	 * 
	 * @param action the docking action to adapt to a Swing {@link Action}
	 * @return the new action
	 */
	public static Action adaptDockingActionToNonContextAction(DockingAction action) {
		return new ActionAdapter(action);
	}

	/**
	 * Checks each action in the given collection against the given new action to make sure that
	 * they share the same default key binding.
	 * 
	 * @param newAction the action to check
	 * @param existingActions the actions that have already been checked
	 */
	public static void assertSameDefaultKeyBindings(DockingActionIf newAction,
			Collection<DockingActionIf> existingActions) {

		if (!newAction.getKeyBindingType().supportsKeyBindings()) {
			return;
		}

		KeyBindingData newDefaultBinding = newAction.getDefaultKeyBindingData();
		KeyStroke defaultKs = getKeyStroke(newDefaultBinding);
		for (DockingActionIf action : existingActions) {
			if (!action.getKeyBindingType().supportsKeyBindings()) {
				continue;
			}

			KeyBindingData existingDefaultBinding = action.getDefaultKeyBindingData();
			KeyStroke existingKs = getKeyStroke(existingDefaultBinding);
			if (!Objects.equals(defaultKs, existingKs)) {
				logDifferentKeyBindingsWarnigMessage(newAction, action, existingKs);
				break; // one warning seems like enough
			}
		}
	}

	/**
	 * Logs a warning message for the two given actions to signal that they do not share the
	 * same default key binding
	 * 
	 * @param newAction the new action
	 * @param existingAction the action that has already been validated
	 * @param existingDefaultKs the current validated key stroke
	 */
	public static void logDifferentKeyBindingsWarnigMessage(DockingActionIf newAction,
			DockingActionIf existingAction, KeyStroke existingDefaultKs) {

		//@formatter:off
		String s = "Shared Key Binding Actions have different default values.  These " +
				"must be the same." +
				"\n\tAction name: '"+existingAction.getName()+"'" +
				"\n\tAction 1: " + existingAction.getInceptionInformation() +
				"\n\t\tKey Binding: " + existingDefaultKs +
				"\n\tAction 2: " + newAction.getInceptionInformation() +
				"\n\t\tKey Binding: " + newAction.getKeyBinding() +
				"\nUsing the " +
				"first value set - " + existingDefaultKs;
		//@formatter:on

		Msg.warn(KeyBindingUtils.class, s, ReflectionUtilities.createJavaFilteredThrowable());
	}

	/**
	 * Updates the given data with system-independent versions of key modifiers.  For example,
	 * the <code>control</code> key will be converted to the <code>command</code> key on the Mac.
	 * 
	 * @param keyStroke the keystroke to validate
	 * @return the potentially changed keystroke
	 */
	// TODO ignore the deprecation, as this method is responsible for fixing deprecated usage.
	//      When all actions no longer user the deprecated modifiers, the deprecated elements
	//      of this method can be removed
	@SuppressWarnings("deprecation")
	public static KeyStroke validateKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return null;
		}

		// remove system-dependent control key mask and transform deprecated modifiers
		int modifiers = keyStroke.getModifiers();
		if ((modifiers & InputEvent.CTRL_DOWN_MASK) == InputEvent.CTRL_DOWN_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_DOWN_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & InputEvent.CTRL_MASK) == InputEvent.CTRL_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK) {
			modifiers = modifiers ^ ActionEvent.CTRL_MASK;
			modifiers = modifiers | DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		}

		if ((modifiers & InputEvent.SHIFT_MASK) == InputEvent.SHIFT_MASK) {
			modifiers = modifiers ^ InputEvent.SHIFT_MASK;
			modifiers = modifiers | InputEvent.SHIFT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.ALT_MASK) == InputEvent.ALT_MASK) {
			modifiers = modifiers ^ InputEvent.ALT_MASK;
			modifiers = modifiers | InputEvent.ALT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.META_MASK) == InputEvent.META_MASK) {
			modifiers = modifiers ^ InputEvent.META_MASK;
			modifiers = modifiers | InputEvent.META_DOWN_MASK;
		}

		int eventType = keyStroke.getKeyEventType();
		if (eventType == KeyEvent.KEY_TYPED) {
			// we know that typed events have a key code of VK_UNDEFINED
			return KeyStroke.getKeyStroke(Character.valueOf(keyStroke.getKeyChar()), modifiers);
		}

		// key pressed or released
		boolean isOnKeyRelease = keyStroke.isOnKeyRelease();
		return KeyStroke.getKeyStroke(keyStroke.getKeyCode(), modifiers, isOnKeyRelease);
	}

	/**
	 * Convert the toString() form of the keyStroke.
	 * <br>In Java 1.4.2 and earlier, Ctrl-M is returned as "keyCode CtrlM-P"
	 * and we want it to look like: "Ctrl-M".
	 * <br>In Java 1.5.0, Ctrl-M is returned as "ctrl pressed M"
	 * and we want it to look like: "Ctrl-M".
	 * <br>In Java 11 we have seen toString() values get printed with repeated text, such
	 * as: "shift ctrl pressed SHIFT".  We want to trim off the repeated modifiers.
	 * 
	 * @param keyStroke the key stroke
	 * @return the string value; the empty string if the key stroke is null
	 */
	public static String parseKeyStroke(KeyStroke keyStroke) {

		if (keyStroke == null) {
			return "";
		}

		final String keyPressSuffix = "-P";
		String keyString = keyStroke.toString();
		int type = keyStroke.getKeyEventType();
		if (type == KeyEvent.KEY_TYPED) {
			return String.valueOf(keyStroke.getKeyChar());
		}

		// get the character used in the key stroke
		int firstIndex = keyString.lastIndexOf(' ') + 1;
		int ctrlIndex = indexOf(keyString, CTRL, firstIndex);
		if (ctrlIndex >= 0) {
			firstIndex = ctrlIndex + CTRL.length();
		}
		int altIndex = indexOf(keyString, ALT, firstIndex);
		if (altIndex >= 0) {
			firstIndex = altIndex + ALT.length();
		}
		int shiftIndex = indexOf(keyString, SHIFT, firstIndex);
		if (shiftIndex >= 0) {
			firstIndex = shiftIndex + SHIFT.length();
		}
		int metaIndex = indexOf(keyString, META, firstIndex);
		if (metaIndex >= 0) {
			firstIndex = metaIndex + META.length();
		}

		int lastIndex = keyString.length();
		if (keyString.endsWith(keyPressSuffix)) {
			lastIndex -= keyPressSuffix.length();
		}
		if (lastIndex >= 0) {
			keyString = keyString.substring(firstIndex, lastIndex);
		}

		int modifiers = keyStroke.getModifiers();
		StringBuilder buffy = new StringBuilder();
		if (isShift(modifiers)) {
			buffy.insert(0, SHIFT + MODIFIER_SEPARATOR);
			keyString = removeIgnoreCase(keyString, SHIFT);
		}
		if (isAlt(modifiers)) {
			buffy.insert(0, ALT + MODIFIER_SEPARATOR);
			keyString = removeIgnoreCase(keyString, ALT);
		}
		if (isControl(modifiers)) {
			buffy.insert(0, CTRL + MODIFIER_SEPARATOR);
			keyString = removeIgnoreCase(keyString, CONTROL);
		}
		if (isMeta(modifiers)) {
			buffy.insert(0, META + MODIFIER_SEPARATOR);
			keyString = removeIgnoreCase(keyString, META);
		}
		buffy.append(keyString);

		String text = buffy.toString().trim();
		if (text.endsWith(MODIFIER_SEPARATOR)) {
			text = text.substring(0, text.length() - 1);
		}
		return text;
	}

	private static int indexOf(String source, String search, int offset) {
		return StringUtils.indexOfIgnoreCase(source, search, offset);
	}

	// ignore the deprecated; remove when we are confident that all tool actions no longer use the
	// deprecated InputEvent mask types
	@SuppressWarnings("deprecation")
	private static boolean isShift(int mask) {
		return (mask & InputEvent.SHIFT_DOWN_MASK) != 0 || (mask & InputEvent.SHIFT_MASK) != 0;
	}

	// ignore the deprecated; remove when we are confident that all tool actions no longer use the
	// deprecated InputEvent mask types
	@SuppressWarnings("deprecation")
	private static boolean isAlt(int mask) {
		return (mask & InputEvent.ALT_DOWN_MASK) != 0 || (mask & InputEvent.ALT_MASK) != 0;
	}

	// ignore the deprecated; remove when we are confident that all tool actions no longer use the
	// deprecated InputEvent mask types
	@SuppressWarnings("deprecation")
	private static boolean isControl(int mask) {
		return (mask & InputEvent.CTRL_DOWN_MASK) != 0 || (mask & InputEvent.CTRL_MASK) != 0;
	}

	// ignore the deprecated; remove when we are confident that all tool actions no longer use the
	// deprecated InputEvent mask types
	@SuppressWarnings("deprecation")
	private static boolean isMeta(int mask) {
		return (mask & InputEvent.META_DOWN_MASK) != 0 || (mask & InputEvent.META_MASK) != 0;
	}

	/**
	 * Parses the given text into a KeyStroke.  This method relies upon
	 * {@link KeyStroke#getKeyStroke(String)} for parsing.  Before making that call, this method
	 * will perform fixup on the given text for added flexibility.  For example, the given
	 * text may contain spaces or dashes as the separators between parts in the string.  Also,
	 * the text is converted such that it is not case-sensitive.  So, the following example
	 * formats are allowed:
	 * <pre>
	 *    Alt-F
	 *    alt p
	 *    Ctrl-Alt-Z
	 *    ctrl Z
	 * </pre>
	 * 
	 * <p><b>Note:</b> The returned keystroke will always correspond to a {@code pressed} event,
	 * regardless of the value passed in (pressed, typed or released).
	 * 
	 * @param keyStroke the key stroke
	 * @return the new key stroke (as returned by  {@link KeyStroke#getKeyStroke(String)}
	 */
	public static KeyStroke parseKeyStroke(String keyStroke) {
		List<String> pieces = new ArrayList<>();
		StringTokenizer tokenizer = new StringTokenizer(keyStroke, "- ");
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			if (!pieces.contains(token)) {
				pieces.add(token);
			}
		}

		StringBuilder buffy = new StringBuilder();
		for (Iterator<String> iterator = pieces.iterator(); iterator.hasNext();) {
			String piece = iterator.next();
			if (indexOfIgnoreCase(piece, SHIFT) != -1) {
				buffy.append("shift ");
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, CTRL) != -1) {
				buffy.append("ctrl ");
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, CONTROL) != -1) {
				buffy.append("ctrl ");
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, ALT) != -1) {
				buffy.append("alt ");
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, META) != -1) {
				buffy.append("meta ");
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, PRESSED) != -1) {
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, TYPED) != -1) {
				iterator.remove();
			}
			else if (indexOfIgnoreCase(piece, RELEASED) != -1) {
				iterator.remove();
			}

		}

		buffy.append(PRESSED).append(' ');

		// at this point we should only have left one piece--the key ID
		int leftover = pieces.size();
		if (leftover > 1 || leftover == 0) {
			Msg.warn(KeyBindingUtils.class, "Invalid keystroke string found.  Expected " +
				"format of '[modifier] ... key'.  Found: '" + keyStroke + "'");

			if (leftover == 0) {
				return null; // nothing to do
			}
		}

		String key = pieces.get(0);
		buffy.append(key.toUpperCase());

		return KeyStroke.getKeyStroke(buffy.toString());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private static boolean isIgnored(DockingActionIf action) {
		// a shared keybinding implies that this action should not be in
		// the UI, as there will be a single proxy in place of all actions sharing that binding
		return !action.getKeyBindingType().isManaged();
	}

	private static KeyStroke getKeyStroke(KeyBindingData data) {
		if (data == null) {
			return null;
		}
		return data.getKeyBinding();
	}

	// prompts the user for a file location from which to read key binding data
	private static InputStream getInputStreamForFile(File startingDir) {
		File selectedFile = getFileFromUser(startingDir);

		if (selectedFile == null) {
			return null;
		}

		InputStream inputStream = null;

		try {
			inputStream = new BufferedInputStream(new FileInputStream(selectedFile));
		}
		catch (FileNotFoundException fnfe) {
			// show warning and prompt again for the file chooser
			Msg.showError(log, null, "File Not Found",
				"Cannot find file " + selectedFile.getAbsolutePath(), fnfe);

			return getInputStreamForFile(selectedFile);
		}

		return inputStream;
	}

	// prompts the user for a file location to which key binding data will
	// be written
	private static OutputStream getOutputStreamForFile(File startingDir) {
		File selectedFile = getFileFromUser(startingDir);

		if (selectedFile == null) {
			return null;
		}

		OutputStream outputStream = null;

		try {
			outputStream = new BufferedOutputStream(new FileOutputStream(selectedFile));
		}
		catch (FileNotFoundException fnfe) {
			// show warning and prompt again for the file chooser
			Msg.showError(log, null, "File Not Found",
				"Cannot find file " + selectedFile.getAbsolutePath(), fnfe);

			return getOutputStreamForFile(selectedFile);
		}

		return outputStream;
	}

	private static File getStartingDir() {
		String lastDirectoryPath = Preferences.getProperty(LAST_KEY_BINDING_EXPORT_DIRECTORY);
		if (lastDirectoryPath != null) {
			return new File(lastDirectoryPath);
		}

		return new File(System.getProperty("user.home"));
	}

	private static File getFileFromUser(File startingDir) {
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component activeComponent = kfm.getActiveWindow();
		GhidraFileChooser fileChooser = new GhidraFileChooser(activeComponent);
		fileChooser.setTitle("Please Select A File");
		fileChooser.setFileFilter(FILE_FILTER);
		fileChooser.setApproveButtonText("OK");
		fileChooser.setCurrentDirectory(startingDir);

		File selectedFile = fileChooser.getSelectedFile();

		// make sure the file has the correct extension
		if ((selectedFile != null) &&
			!selectedFile.getName().endsWith(PREFERENCES_FILE_EXTENSION)) {
			selectedFile = new File(selectedFile.getAbsolutePath() + PREFERENCES_FILE_EXTENSION);
		}

		// save off the last location to which the user navigated so we can
		// return them to that spot if they user the dialog again.
		Preferences.setProperty(LAST_KEY_BINDING_EXPORT_DIRECTORY,
			fileChooser.getCurrentDirectory().getAbsolutePath());

		return selectedFile;
	}
}
