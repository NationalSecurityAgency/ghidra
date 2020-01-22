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
		this(root.getAttributeValue("NAME"));

		SaveState saveState = new SaveState(root);

		for (String optionName : saveState.getNames()) {
			Object object = saveState.getObject(optionName);
			Option option =
				createUnregisteredOption(optionName, OptionType.getOptionType(object), null);
			option.doSetCurrentValue(object);  // use doSet versus set so that it is not registered
			valueMap.put(optionName, option);

		}

		Iterator<?> iter = root.getChildren("WRAPPED_OPTION").iterator();
		while (iter.hasNext()) {
			try {
				Element elem = (Element) iter.next();
				String optionName = elem.getAttributeValue("NAME");
				Class<?> c = Class.forName(elem.getAttributeValue("CLASS"));
				Constructor<?> constructor = c.getDeclaredConstructor();
				WrappedOption wo = (WrappedOption) constructor.newInstance();
				wo.readState(new SaveState(elem));
				Option option = createUnregisteredOption(optionName, wo.getOptionType(), null);
				option.doSetCurrentValue(wo.getObject());// use doSet versus set so that it is not registered
				valueMap.put(optionName, option);
			}
			catch (Exception exc) {
				Msg.error(this, "Unexpected Exception: " + exc.getMessage(), exc);
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

		for (String optionName : valueMap.keySet()) {
			Option optionValue = valueMap.get(optionName);
			if (includeDefaultBindings || !optionValue.isDefault()) {
				Object value = optionValue.getValue(null);
				if (isSupportedBySaveState(value)) {
					saveState.putObject(optionName, value);
				}
			}
		}

		Element root = saveState.saveToXml();
		root.setAttribute("NAME", name);

		for (String optionName : valueMap.keySet()) {
			Option optionValue = valueMap.get(optionName);
			if (includeDefaultBindings || !optionValue.isDefault()) {
				Object value = optionValue.getValue(null);
				if (value != null && !isSupportedBySaveState(value)) {
					WrappedOption wrappedOption = wrapOption(value);
					SaveState ss = new SaveState("WRAPPED_OPTION");
					wrappedOption.writeState(ss);
					Element elem = ss.saveToXml();
					elem.setAttribute("NAME", optionName);
					elem.setAttribute("CLASS", wrappedOption.getClass().getName());
					root.addContent(elem);
				}
			}
		}

		return root;
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

	private WrappedOption wrapOption(Object value) {
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

	////////////////////////////////////////////////////////////////

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
		SystemUtilities.runSwingNow(runnable);
		return !runnable.wasVetoed();
	}
}
