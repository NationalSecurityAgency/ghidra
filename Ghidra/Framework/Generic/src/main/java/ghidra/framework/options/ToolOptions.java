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
package ghidra.framework.options;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyEditor;
import java.io.File;
import java.lang.reflect.Constructor;
import java.util.*;

import javax.swing.KeyStroke;

import org.jdom.Element;

import ghidra.util.*;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.exception.AssertException;

/**
 * Class to manage a set of option name/value pairs for a category.
 * The values may be primitives or
 * WrappedObjects that are containers for its primitive components.
 * The option may be associated with a particular group.
 * <p> The name/value pair has a owner so that the option name
 * can be removed from the Options object when it is no longer being used.
 * <p>NOTE: Property Names can have DELIMITER characters to create a hierarchy.
 * The Options Dialog shows the hierarchy in tree format.
 */
public class ToolOptions extends AbstractOptions {
	private static final String CLASS_ATTRIBUTE = "CLASS";
	private static final String NAME_ATTRIBUTE = "NAME";
	private static final String WRAPPED_OPTION_NAME = "WRAPPED_OPTION";
	private static final String CLEARED_VALUE_ELEMENT_NAME = "CLEARED_VALUE";
	public static final Set<Class<?>> PRIMITIVE_CLASSES = buildPrimitiveClassSet();
	public static final Set<Class<?>> WRAPPABLE_CLASSES = buildWrappableClassSet();

	public static final String XML_ELEMENT_NAME = "CATEGORY";

	private static Set<Class<?>> buildPrimitiveClassSet() {
		HashSet<Class<?>> set = new HashSet<>();
		set.add(Byte.class);
		set.add(Short.class);
		set.add(Integer.class);
		set.add(Long.class);
		set.add(Float.class);
		set.add(Double.class);
		set.add(Boolean.class);
		set.add(String.class);
		return set;
	}

	private static Set<Class<?>> buildWrappableClassSet() {
		HashSet<Class<?>> set = new HashSet<>();
		set.add(Color.class);
		set.add(Font.class);
		set.add(KeyStroke.class);
		set.add(File.class);
		return set;
	}

	public ToolOptions(String name) {
		super(name);
	}

	public ToolOptions copy() {
		return new ToolOptions(getXmlRoot(true));
	}

	/**
	 * Construct a new Options object from the given XML element.
	 * @param root XML that contains the set of options to restore
	 */
	public ToolOptions(Element root) {
		this(root.getAttributeValue(NAME_ATTRIBUTE));

		SaveState saveState = new SaveState(root);

		readNonWrappedOptions(saveState);

		try {
			readWrappedOptions(root);
		}
		catch (ReflectiveOperationException exc) {
			Msg.error(this, "Unexpected Exception: " + exc.getMessage(), exc);
		}
	}

	private void readNonWrappedOptions(SaveState saveState) {
		for (String optionName : saveState.getNames()) {
			Object object = saveState.getObject(optionName);
			Option option =
				createUnregisteredOption(optionName, OptionType.getOptionType(object), null);
			option.doSetCurrentValue(object);  // use doSet versus set so that it is not registered
			valueMap.put(optionName, option);
		}
	}

	private void readWrappedOptions(Element root) throws ReflectiveOperationException {

		Iterator<?> it = root.getChildren(WRAPPED_OPTION_NAME).iterator();
		while (it.hasNext()) {

			Element element = (Element) it.next();
			List<?> children = element.getChildren();
			if (children.isEmpty()) {
				continue; // shouldn't happen
			}

			String optionName = element.getAttributeValue(NAME_ATTRIBUTE);
			Class<?> c = Class.forName(element.getAttributeValue(CLASS_ATTRIBUTE));
			Constructor<?> constructor = c.getDeclaredConstructor();
			WrappedOption wo = (WrappedOption) constructor.newInstance();
			Option option = createUnregisteredOption(optionName, wo.getOptionType(), null);
			valueMap.put(optionName, option);

			Element child = (Element) children.get(0);
			String elementName = child.getName();
			if (CLEARED_VALUE_ELEMENT_NAME.equals(elementName)) {
				// a signal that the default option value has been cleared
				option.doSetCurrentValue(null); // use doSet so that it is not registered
			}
			else {
				wo.readState(new SaveState(element));
				option.doSetCurrentValue(wo.getObject()); // use doSet so that it is not registered
			}
		}
	}

	/**
	 * Return an XML element for the option names and values.
	 * Note: only those options which have been explicitly set
	 * will be included.
	 * 
	 * @param includeDefaultBindings true to include default key binding values in the xml 
	 * @return the xml root element
	 */
	public Element getXmlRoot(boolean includeDefaultBindings) {

		SaveState saveState = new SaveState(XML_ELEMENT_NAME);

		writeNonWrappedOptions(includeDefaultBindings, saveState);

		Element root = saveState.saveToXml();
		root.setAttribute(NAME_ATTRIBUTE, name);

		writeWrappedOptions(includeDefaultBindings, root);

		return root;
	}

	private void writeNonWrappedOptions(boolean includeDefaultBindings, SaveState saveState) {
		for (String optionName : valueMap.keySet()) {
			Option optionValue = valueMap.get(optionName);
			if (includeDefaultBindings || !optionValue.isDefault()) {
				Object value = optionValue.getValue(null);
				if (isSupportedBySaveState(value)) {
					saveState.putObject(optionName, value);
				}
			}
		}
	}

	private void writeWrappedOptions(boolean includeDefaultBindings, Element root) {
		for (String optionName : valueMap.keySet()) {
			Option option = valueMap.get(optionName);
			if (includeDefaultBindings || !option.isDefault()) {

				Object value = option.getCurrentValue();
				if (isSupportedBySaveState(value)) {
					// handled above
					continue;
				}

				WrappedOption wrappedOption = wrapOption(option);
				if (wrappedOption == null) {
					// cannot write an option without a value to determine its type
					continue;
				}

				SaveState ss = new SaveState(WRAPPED_OPTION_NAME);
				Element elem = null;
				if (value == null) {
					// Handle the null case ourselves, not using the wrapped option (and when 
					// reading from xml) so that the logic does not need to in each wrapped option
					elem = ss.saveToXml();
					elem.addContent(new Element(CLEARED_VALUE_ELEMENT_NAME));
				}
				else {
					wrappedOption.writeState(ss);
					elem = ss.saveToXml();
				}

				elem.setAttribute(NAME_ATTRIBUTE, optionName);
				elem.setAttribute(CLASS_ATTRIBUTE, wrappedOption.getClass().getName());
				root.addContent(elem);
			}
		}
	}

	private boolean isSupportedBySaveState(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj instanceof Enum) {
			return true;
		}
		if (obj instanceof byte[]) {
			return true;
		}
		return PRIMITIVE_CLASSES.contains(obj.getClass());

	}

	private WrappedOption wrapOption(Option option) {

		Object value = null;
		value = option.getCurrentValue();
		if (value == null) {
			value = option.getDefaultValue();
		}

		if (value == null) {
			// nothing to wrap
			return null;
		}

		if (value instanceof CustomOption) {
			return new WrappedCustomOption((CustomOption) value);
		}
		if (value instanceof Color) {
			return new WrappedColor((Color) value);
		}
		if (value instanceof Font) {
			return new WrappedFont((Font) value);
		}
		if (value instanceof KeyStroke) {
			return new WrappedKeyStroke((KeyStroke) value);
		}
		if (value instanceof File) {
			return new WrappedFile((File) value);
		}
		if (value instanceof Date) {
			return new WrappedDate((Date) value);
		}
		throw new AssertException(
			"Attempted to wrap object of unexpected class type: " + value.getClass());
	}

	/**
	 * Add the options change listener. NOTE: The Options uses
	 * WeakReferences to manage the listeners; this means that you must supply a
	 * listener and maintain a handle to it, or else the listener will be
	 * garbage collected and will never get called. So for this reason, do
	 * <i>not</i> create the listener in an anonymous inner class.
	 * @param l listener to add
	 */
	public void addOptionsChangeListener(OptionsChangeListener l) {
		listeners.add(l);
	}

	public void takeListeners(ToolOptions oldOptions) {
		listeners = oldOptions.listeners;
		oldOptions.listeners = null;
	}

	/**
	 * Remove the options change listener.
	 * @param l listener to remove
	 */
	public void removeOptionsChangeListener(OptionsChangeListener l) {
		listeners.remove(l);
	}

	/**
	 * Check each option to ensure that an owner is still registered for it;
	 * if there is no owner, then remove the option.
	 */
	public void removeUnusedOptions() {
		List<String> optionNames = new ArrayList<>(valueMap.keySet());
		for (String optionName : optionNames) {
			Option optionState = valueMap.get(optionName);
			if (!optionState.isRegistered()) {
				removeOption(optionName);
			}
		}
	}

	/**
	 * Adds all the options name/value pairs to this Options.
	 * @param newOptions the new options into which the current options values will be placed
	 */
	public void copyOptions(Options newOptions) {
		List<String> optionNames = newOptions.getOptionNames();
		for (String optionName : optionNames) {
			Object value = newOptions.getObject(optionName, null);
			if (value != null) {
				putObject(optionName, value);
			}
		}
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ToolOptions other = (ToolOptions) obj;
		if (!SystemUtilities.isEqual(name, other.name)) {
			return false;
		}

		List<String> optionNames = getOptionNames();
		List<String> otherOptionNames = other.getOptionNames();
		if (optionNames.size() != otherOptionNames.size()) {
			return false;
		}
		Object dummy = new Object();
		for (String string : optionNames) {
			Object myValue = getObject(string, dummy);
			Object otherValue = other.getObject(string, dummy);
			if (!SystemUtilities.isEqual(myValue, otherValue)) {
				return false;
			}
		}
		return true;
	}

	public void validateOptions() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			// Only complain if in development mode - it appears normal that some options
			// are not registered (e.g., Navigation marker enablement)
			return;
		}

		Set<String> keySet = valueMap.keySet();
		for (String propertyName : keySet) {
			Option optionState = valueMap.get(propertyName);
			if (optionState.isRegistered()) {
				continue;
			}
			Msg.warn(this, "Unregistered property \"" + propertyName + "\" in Options \"" + name +
				"\"\n     " + optionState.getInceptionInformation());
		}
	}

	public void registerOptions(ToolOptions oldOptions) {
		Set<String> optionNameSet = oldOptions.valueMap.keySet();
		for (String optionName : optionNameSet) {
			Option option = oldOptions.valueMap.get(optionName);
			if (option.isRegistered()) {
				registerOption(optionName, option.getOptionType(), option.getDefaultValue(),
					option.getHelpLocation(), option.getDescription());
			}
		}
	}

	private static class ToolOption extends Option {
		private Object currentValue;

		ToolOption(String name, OptionType type, String description, HelpLocation helpLocation,
				Object defaultValue, boolean isRegistered, PropertyEditor editor) {
			super(name, type, description, helpLocation, defaultValue, isRegistered, editor);

			this.currentValue = defaultValue;
		}

		@Override
		public Object getCurrentValue() {
			return currentValue;
		}

		@Override
		public void doSetCurrentValue(Object value) {
			currentValue = value;
		}
	}

	@Override
	protected Option createRegisteredOption(String optionName, OptionType type, String description,
			HelpLocation help, Object defaultValue, PropertyEditor editor) {
		return new ToolOption(optionName, type, description, help, defaultValue, true, editor);
	}

	@Override
	protected Option createUnregisteredOption(String optionName, OptionType type,
			Object defaultValue) {
		return new ToolOption(optionName, type, null, null, defaultValue, false, null);
	}

	@Override
	protected boolean notifyOptionChanged(String optionName, Object oldValue, Object newValue) {
		NotifyListenersRunnable runnable =
			new NotifyListenersRunnable(optionName, oldValue, newValue);
		Swing.runNow(runnable);
		return !runnable.wasVetoed();
	}

	private class NotifyListenersRunnable implements Runnable {
		private String optionName;
		private Object oldValue;
		private Object newValue;
		private boolean vetoed;

		NotifyListenersRunnable(String optionName, Object oldValue, Object newValue) {
			this.optionName = optionName;
			this.oldValue = oldValue;
			this.newValue = newValue;
		}

		@Override
		public void run() {
			List<OptionsChangeListener> notifiedListeners = new ArrayList<>();
			try {
				for (OptionsChangeListener listener : listeners) {
					listener.optionsChanged(ToolOptions.this, optionName, oldValue, newValue);
					notifiedListeners.add(listener);
				}
			}
			catch (OptionsVetoException e) {
				vetoed = true;
				for (OptionsChangeListener notifiedListener : notifiedListeners) {
					notifiedListener.optionsChanged(ToolOptions.this, optionName, newValue,
						oldValue);
				}
			}
		}

		public boolean wasVetoed() {
			return vetoed;
		}

	}

}
