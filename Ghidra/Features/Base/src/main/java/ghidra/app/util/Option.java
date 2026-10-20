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

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import ghidra.app.util.importer.options.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.AddressFactory;

/**
 * Container class to hold an option
 */
public class Option {

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.BooleanOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static BooleanOption.Builder newBoolean(String name) {
		return new BooleanOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.StringOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static StringOption.Builder newString(String name) {
		return new StringOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.IntegerOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static IntegerOption.Builder newInteger(String name) {
		return new IntegerOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.HexLongOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static HexLongOption.Builder newHexLong(String name) {
		return new HexLongOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.AddressOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static AddressOption.Builder newAddress(String name) {
		return new AddressOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.AddressSpaceOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static AddressSpaceOption.Builder newAddressSpace(String name) {
		return new AddressSpaceOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.DomainFileOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static DomainFileOption.Builder newDomainFile(String name) {
		return new DomainFileOption.Builder(name);
	}

	/**
	 * {@return a new {@link ghidra.app.util.importer.options.DomainFolderOption.Builder}}
	 * 
	 * @param name The name of the option
	 */
	public static DomainFolderOption.Builder newDomainFolder(String name) {
		return new DomainFolderOption.Builder(name);
	}

	private final String group;
	private final String name;
	private final Class<?> valueClass;
	private final String commandLineArgument;
	private final String stateKey;
	private final boolean hidden;
	private final String description;

	private Object value;
	private OptionListener listener;

	/**
	 * Constructs a new {@link Option}
	 * 
	 * @param name the name of the option
	 * @param value the value of the option
	 * @throws IllegalArgumentException if value is {@code null}
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String name, Object value) {
		this(null, name, value);
	}

	/**
	 * Constructs a new {@link Option}
	 * 
	 * @param group the name for group of options
	 * @param name the name of the option
	 * @param value the value of the option
	 * @throws IllegalArgumentException if value is {@code null}
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String group, String name, Object value) {
		this(name, getValueClass(value), value, null, group);
	}

	/**
	 * Constructs a new {@link Option}
	 * 
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String name, Class<?> valueClass) {
		this(name, valueClass, null, null, null);
	}

	/**
	 * Constructs a new {@link Option}
	 * 
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value, which should match {@code <T>}
	 * @param value the value of the option (could be {@code null})
	 * @param arg the option's command line argument (could be {@code null})
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String name, Object value, Class<?> valueClass, String arg) {
		this(name, valueClass, value, arg, null);
	}

	/**
	 * Constructs a new {@link Option}
	 *
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value, which should match {@code <T>}
	 * @param value the value of the option (could be {@code null})
	 * @param arg the option's command line argument (could be {@code null})
	 * @param group the name for group of options (could be {@code null})
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String name, Class<?> valueClass, Object value, String arg, String group) {
		this(name, valueClass, value, arg, group, null, false);
	}

	/**
	 * Constructs a new {@link Option}
	 *
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value, which should match {@code <T>}
	 * @param value the value of the option (could be {@code null})
	 * @param arg the option's command line argument (could be {@code null})
	 * @param group the name for group of options (could be {@code null})
	 * @param stateKey the state key name (could be {@code null})
	 * @param hidden true if this option should be hidden from the user; otherwise, false
	 * @deprecated use {@link AbstractOptionBuilder} subclasses instead
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public Option(String name, Class<?> valueClass, Object value, String arg, String group,
			String stateKey, boolean hidden) {
		this(name, valueClass, value, arg, group, stateKey, hidden, null);
	}

	/**
	 * Constructs a new {@link Option}.
	 *
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value, which should match {@code <T>}
	 * @param value the value of the option (could be {@code null})
	 * @param arg the option's command line argument (could be {@code null})
	 * @param group the name for group of options (could be {@code null})
	 * @param stateKey the state key name (could be {@code null})
	 * @param hidden true if this option should be hidden from the user; otherwise, false
	 * @param description a description of the option (could be {@code null})
	 */
	protected Option(String name, Class<?> valueClass, Object value, String arg, String group,
			String stateKey, boolean hidden, String description) {
		this.name = name;
		this.valueClass = valueClass;
		this.commandLineArgument = arg;
		this.group = group;
		this.value = value;
		this.stateKey = stateKey;
		this.hidden = hidden;
		this.description = description;
	}

	/**
	 * Sets this option's listener
	 * 
	 * @param listener The {@link OptionListener} to set
	 */
	public void setOptionListener(OptionListener listener) {
		this.listener = listener;
	}

	/**
	 * Override if you want to provide a custom widget for selecting your options. 
	 * <p>
	 * Important! If you override this you MUST also override the {@link #copy()} method so it 
	 * returns a new instance of your custom editor. 
	 * 
	 * @param addressFactoryService The {@link AddressFactoryService}
	 * @return the custom editor {@link Component}, or {@code null} if there isn't one
	 */
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
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
	 * Set the value for this option
	 * 
	 * @param object value of this option
	 * @throws IllegalArgumentException if the type of the object doesn't not match this option's
	 *   value class
	 */
	public void setValue(Object object) throws IllegalArgumentException {
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
		// Subclasses can override this if they need parsings support
		return false;
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

	/**
	 * {@return whether or not this option is hidden}
	 */
	public boolean isHidden() {
		return hidden;
	}

	/**
	 * {@return the option's description (could be null)}
	 */
	public String getDescription() {
		return description;
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
	}

	/**
	 * {@return a copy of this {@link Option} object}
	 * <p>
	 * NOTE: {@link Option} subclasses should always overwrite this method so they can return 
	 * their exact type, instead of the more generic {@link Option} type.
	 * <p>
	 * NOTE: When the deprecated constructors of this class get removed, this method should become
	 * abstract.
	 */
	public Option copy() {
		return new Option(name, valueClass, value, commandLineArgument, group, stateKey, hidden,
			description);
	}

	/**
	 * {@return the class type of the given value}
	 * 
	 * @throws IllegalArgumentException if the given value is {@code null}
	 */
	private static Class<?> getValueClass(Object v) throws IllegalArgumentException {
		if (v == null) {
			throw new IllegalArgumentException("Value cannot be null without specifying class.");
		}
		return v.getClass();
	}
}
