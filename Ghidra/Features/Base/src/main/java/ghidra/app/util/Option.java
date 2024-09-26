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
package ghidra.app.util;

import java.awt.Component;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.*;
import ghidra.util.NumericUtilities;

/**
 * Container class to hold a name, value, and class of the value.
 */
public class Option {
	private final String group;
	private final String name;
	private final Class<?> valueClass;
	private final String commandLineArgument;
	private final String stateKey;

	private Object value;
	private OptionListener listener;

	/**
	 * Construct a new Option.
	 * @param name name of the option
	 * @param value value of the option. Value can't be null with this constructor.
	 * @throws IllegalArgumentException if value is null
	 */
	public Option(String name, Object value) {
		this(null, name, value);
	}

	/**
	 * Construct a new Option.
	 * @param group Name for group of options
	 * @param name name of the option
	 * @param value value of the option
	 * @throws IllegalArgumentException if value is null
	 */
	public Option(String group, String name, Object value) {
		this(name, getValueClass(value), value, null, group);
	}

	/**
	 * Construct a new Option.
	 * @param name name of the option
	 * @param valueClass class of the option's value
	 *
	 */
	public Option(String name, Class<?> valueClass) {
		this(name, valueClass, null, null, null);
	}

	/**
	 * Construct a new Option
	 * @param name name of the option
	 * @param value value of the option
	 * @param valueClass class of the option's value
	 * @param arg the option's command line argument
	 *
	 */
	public Option(String name, Object value, Class<?> valueClass, String arg) {
		this(name, valueClass, value, arg, null);
	}

	/**
	 * Construct a new Option
	 *
	 * @param name name of the option
	 * @param valueClass class of the option's value
	 * @param value value of the option
	 * @param arg the option's command line argument
	 * @param group Name for group of options
	 */
	public Option(String name, Class<?> valueClass, Object value, String arg, String group) {
		this(name, valueClass, value, arg, group, null);
	}

	/**
	 * Construct a new Option
	 *
	 * @param name name of the option
	 * @param valueClass class of the option's value
	 * @param value value of the option
	 * @param arg the option's command line argument
	 * @param group Name for group of options
	 * @param stateKey state key name
	 */
	public Option(String name, Class<?> valueClass, Object value, String arg, String group,
			String stateKey) {
		this.name = name;
		this.valueClass = valueClass;
		this.commandLineArgument = arg;
		this.group = group;
		this.value = value;
		this.stateKey = stateKey;
	}

	public void setOptionListener(OptionListener listener) {
		this.listener = listener;
	}

	/**
	 * Override if you want to provide a custom widget for selecting your
	 * options. 
	 * <p>
	 * Important! If you override this you MUST also override the {@link #copy()}
	 * method so it returns a new instance of your custom editor. 
	 * 
	 * @return the custom editor
	 */
	public Component getCustomEditorComponent() {
		return null;
	}

	/**
	 * {@return the class of the value for this option}
	 */
	public Class<?> getValueClass() {
		return valueClass;
	}

	/**
	 * {@return the group name for this option; may be null if group was not specified}
	 */
	public String getGroup() {
		return group;
	}

	/**
	 * {@return the name of this option}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the value of this option}
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * Set the value for this option.
	 * @param object value of this option
	 */
	public void setValue(Object object) {
		if (object != null && !valueClass.isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException("Value class does not match! Expected " +
				valueClass + ", but got " + object.getClass());
		}
		value = object;
		if (listener != null) {
			listener.optionChanged(this);
		}
	}

	/**
	 * Set the value for this option by parsing the given string and converting it to the option's
	 * type.  Fails if this option doesn't have a type associated with it, or if an unsupported
	 * type is needed to be parsed.
	 *
	 * @param str The value to set, in string form.
	 * @param addressFactory An address factory to use for when the option trying to be set is an Address.
	 * If null, an exception will be thrown for Address type options.
	 * @return True if the value was successfully parsed and set; otherwise, false.
	 */
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		if (getValueClass() == null) {
			return false;
		}
		if (Boolean.class.isAssignableFrom(getValueClass())) {
			try {
				setValue(BooleanUtils.toBoolean(str, "true", "false"));
			}
			catch (IllegalArgumentException e) {
				return false;
			}
		}
		else if (HexLong.class.isAssignableFrom(getValueClass())) {
			try {
				setValue(new HexLong(NumericUtilities.parseHexLong(str)));
			}
			catch (NumberFormatException e) {
				return false;
			}
		}
		else if (Integer.class.isAssignableFrom(getValueClass())) {
			try {
				setValue(Integer.decode(str));
			}
			catch (NumberFormatException e) {
				return false;
			}
		}
		else if (Address.class.isAssignableFrom(getValueClass())) {
			try {
				Address origAddr = (Address) getValue();
				Address newAddr = null;
				if (origAddr != null) {
					newAddr = origAddr.getAddress(str);
				}
				else {
					if (addressFactory == null) {
						throw new RuntimeException("Attempted to use Address type option (" +
							getName() + ") without specifying Address Factory");
					}
					newAddr = addressFactory.getDefaultAddressSpace().getAddress(str);
				}
				if (newAddr == null) {
					return false;
				}
				setValue(newAddr);
			}
			catch (AddressFormatException e) {
				return false;
			}
		}
		else if (String.class.isAssignableFrom(getValueClass())) {
			setValue(str);
		}
		else {
			return false;
		}
		return true;
	}

	/**
	 * {@return the command line argument for this option (could be null)}
	 */
	public String getArg() {
		return commandLineArgument;
	}

	/**
	 * {@return the state key name (could be null)}
	 */
	public String getStateKey() {
		return stateKey;
	}

	/**
	 * {@return the current project state associated with this option (could be null)}
	 */
	public SaveState getState() {
		Project project = AppInfo.getActiveProject();
		if (project == null) {
			return null;
		}
		final SaveState state;
		SaveState existingState = stateKey != null ? project.getSaveableData(stateKey) : null;
		if (existingState != null) {
			state = existingState;
		}
		else if (stateKey != null) {
			state = new SaveState();
			project.setSaveableData(stateKey, state);
		}
		else {
			state = null;
		}
		return state;
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
	}

	/**
	 * Creates a copy of this Option object.
	 * @return  a copy of this Option object.
	 */
	public Option copy() {
		return new Option(name, valueClass, value, commandLineArgument, group, stateKey);
	}

	private static Class<?> getValueClass(Object v) {
		if (v == null) {
			throw new IllegalArgumentException("Value cannot be null without specifying class.");
		}
		return v.getClass();
	}
}
