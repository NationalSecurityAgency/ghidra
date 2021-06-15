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
import java.beans.PropertyEditorManager;
import java.io.File;
import java.util.*;

import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import utilities.util.reflection.ReflectionUtilities;

public abstract class AbstractOptions implements Options {
	public static final Set<Class<?>> SUPPORTED_CLASSES = buildSupportedClassSet();

	private static Set<Class<?>> buildSupportedClassSet() {
		HashSet<Class<?>> set = new HashSet<>();
		set.add(Byte.class);
		set.add(Short.class);
		set.add(Integer.class);
		set.add(Long.class);
		set.add(Float.class);
		set.add(Double.class);
		set.add(Boolean.class);
		set.add(String.class);
		set.add(Color.class);
		set.add(Font.class);
		set.add(KeyStroke.class);
		set.add(File.class);
		set.add(Date.class);
		return set;
	}

	protected String name;
	protected Map<String, Option> valueMap;
	protected WeakSet<OptionsChangeListener> listeners;
	protected Map<String, OptionsEditor> optionsEditorMap;
	protected Map<String, HelpLocation> categoryHelpMap;
	protected Map<String, AliasBinding> aliasMap;

	protected AbstractOptions(String name) {
		this.name = name;
		valueMap = new HashMap<>();
		listeners = WeakDataStructureFactory.createCopyOnReadWeakSet();
		optionsEditorMap = new HashMap<>();
		categoryHelpMap = new HashMap<>();
		aliasMap = new HashMap<>();

	}

	protected abstract Option createRegisteredOption(String optionName, OptionType type,
			String description, HelpLocation help, Object defaultValue, PropertyEditor editor);

	protected abstract Option createUnregisteredOption(String optionName, OptionType type,
			Object defaultValue);

	protected abstract boolean notifyOptionChanged(String optionName, Object oldValue,
			Object newValue);

	public synchronized void registerOptionsEditor(String categoryPath, OptionsEditor editor) {
		optionsEditorMap.put(categoryPath, editor);
	}

	public synchronized OptionsEditor getOptionsEditor(String categoryPath) {
		return optionsEditorMap.get(categoryPath);
	}

	public void dispose() {
		optionsEditorMap.values().forEach(editor -> editor.dispose());
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Sets the name for this Options object.  Used when updating old options names to new names.
	 * @param newName the new name for this options object.
	 */
	public void setName(String newName) {
		this.name = newName;
	}

	@Override
	public void registerOption(String optionName, Object defaultValue, HelpLocation help,
			String description) {
		if (defaultValue == null) {
			throw new IllegalArgumentException(
				"Attempted to register an option with a null value.  If a null value is an " +
					"acceptable default, then call registerOption() that takes an OptionType.");
		}
		if (!isSupportedType(defaultValue)) {
			throw new IllegalArgumentException(
				"Attempted to register an unsupported object: " + defaultValue.getClass());
		}

		OptionType type = OptionType.getOptionType(defaultValue);
		registerOption(optionName, type, defaultValue, help, description);
	}

	@Override
	public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description) {
		registerOption(optionName, type, defaultValue, help, description, null);
	}

	@Override
	public synchronized void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description, PropertyEditor editor) {

		if (type == OptionType.NO_TYPE) {
			throw new IllegalArgumentException(
				"Can't register an option of type: " + OptionType.NO_TYPE);
		}
		if (type == OptionType.CUSTOM_TYPE && editor == null) {
			throw new IllegalStateException(
				"Can't register a custom option without a property editor");
		}
		if (description == null) {
			Msg.error(this, "Registered an option without a description: " + optionName,
				ReflectionUtilities.createJavaFilteredThrowable());
		}

		Option currentOption = getExistingComptibleOption(optionName, type, defaultValue);
		if (currentOption != null) {
			currentOption.updateRegistration(description, help, defaultValue, editor);
			return;
		}

		Option option =
			createRegisteredOption(optionName, type, description, help, defaultValue, editor);

		valueMap.put(optionName, option);
	}

	private Option getExistingComptibleOption(String optionName, OptionType type,
			Object defaultValue) {

		// There are several cases where an existing option may exist when registering an option
		// 1) the option was accessed before it was registered
		// 2) the option was loaded from a store (database or toolstate)
		// 3) the option was registered more than once.
		//
		// The only time this is a problem is if the exiting option type is not compatible with
		// the type being registered.  If we encounter an incompatible option, we just log a
		// warning and return null so that the new option will replace it. Otherwise, we return
		// the existing option so it can be updated with the data from the registration.

		Option option = valueMap.get(optionName);
		if (option == null) {
			return null;
		}

		if (!isCompatibleOption(option, type, defaultValue)) {
			Msg.error(this, "Registered option incompatible with existing option: " + optionName,
				new AssertException());
			return null;
		}
		return option;
	}

	private boolean isCompatibleOption(Option option, OptionType type, Object defaultValue) {
		if (option.getOptionType() != type) {
			return false;
		}
		Object optionValue = option.getValue(null);
		return optionValue == null || defaultValue == null ||
			optionValue.getClass().equals(defaultValue.getClass());
	}

	@Override
	public synchronized void removeOption(String optionName) {
		aliasMap.remove(optionName);
		valueMap.remove(optionName);
	}

	@Override
	public synchronized List<String> getOptionNames() {
		List<String> names = new ArrayList<>(valueMap.keySet());
		names.addAll(aliasMap.keySet());
		Collections.sort(names);
		return names;
	}

	@Override
	public Object getObject(String optionName, Object defaultValue) {
		Option option = getOption(optionName, OptionType.getOptionType(defaultValue), defaultValue);
		return option.getValue(defaultValue);
	}

	public synchronized Option getOption(String optionName, OptionType type, Object defaultValue) {
		validateOptionName(optionName);
		if (aliasMap.containsKey(optionName)) {
			AliasBinding binding = aliasMap.get(optionName);
			return binding.options.getOption(binding.path, type, defaultValue);
		}
		Option option = valueMap.get(optionName);
		if (option == null) {
			option = createUnregisteredOption(optionName, type, defaultValue);
			if (option.getOptionType() != OptionType.NO_TYPE) {
				valueMap.put(optionName, option);
			}
		}
		else if (type != OptionType.NO_TYPE && type != option.getOptionType()) {
			throw new IllegalStateException(
				"Expected option type: " + type + ", but was type: " + option.getOptionType());
		}
		return option;
	}

	@Override
	public void putObject(String optionName, Object newValue) {
		if (newValue == null) {

			if (isNullable(optionName)) {
				// set the value of the option to null, effectively clearing the option
				putObject(optionName, null, OptionType.NO_TYPE);
				return;
			}

			throw new IllegalArgumentException("Attempted to put a null value in an option " +
				"that does not support null values. If you wanted to removethe option, call " +
				"removeOption() instead!");
		}

		if (!isSupportedType(newValue)) {
			throw new IllegalArgumentException(
				"Attempted to store an object that is not supported by Options: " +
					newValue.getClass());
		}
		putObject(optionName, newValue, OptionType.getOptionType(newValue));
	}

	private boolean isNullable(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		if (option == null) {
			return false; // shouldn't happen
		}

		OptionType type = option.getOptionType();
		return isNullable(type);
	}

	private boolean isNullable(OptionType type) {
		switch (type) {

			// objects can be null
			case BYTE_ARRAY_TYPE:
			case ENUM_TYPE:
			case COLOR_TYPE:
			case CUSTOM_TYPE:
			case DATE_TYPE:
			case FILE_TYPE:
			case FONT_TYPE:
			case KEYSTROKE_TYPE:
			case STRING_TYPE:
				return true;
			// auto-box types cannot be null
			case BOOLEAN_TYPE:
			case DOUBLE_TYPE:
			case FLOAT_TYPE:
			case INT_TYPE:
			case LONG_TYPE:
			case NO_TYPE: // not sure about this
			default:
				return false;
		}
	}

	public void putObject(String optionName, Object newValue, OptionType type) {

		Option option = getOption(optionName, type, null);

		Object oldValue = option.getCurrentValue();
		option.setCurrentValue(newValue);

		if (!notifyOptionChanged(optionName, oldValue, newValue)) {
			option.setCurrentValue(oldValue);
		}
	}

	@Override
	public OptionType getType(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.getOptionType();
	}

	@Override
	public boolean getBoolean(String optionName, boolean defaultValue) {
		Option option =
			getOption(optionName, OptionType.BOOLEAN_TYPE, Boolean.valueOf(defaultValue));
		try {
			return (Boolean) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public byte[] getByteArray(String optionName, byte[] defaultValue) {
		Option option = getOption(optionName, OptionType.BYTE_ARRAY_TYPE, defaultValue);
		try {
			return (byte[]) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public int getInt(String optionName, int defaultValue) {
		Option option = getOption(optionName, OptionType.INT_TYPE, defaultValue);
		try {
			return (Integer) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public double getDouble(String optionName, double defaultValue) {
		Option option = getOption(optionName, OptionType.DOUBLE_TYPE, defaultValue);
		try {
			return (Double) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public float getFloat(String optionName, float defaultValue) {
		Option option = getOption(optionName, OptionType.FLOAT_TYPE, defaultValue);
		try {
			return (Float) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public long getLong(String optionName, long defaultValue) {
		Option option = getOption(optionName, OptionType.LONG_TYPE, defaultValue);
		try {
			return (Long) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public CustomOption getCustomOption(String optionName, CustomOption defaultValue) {
		Option option = getOption(optionName, OptionType.CUSTOM_TYPE, defaultValue);
		try {
			return (CustomOption) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public Color getColor(String optionName, Color defaultValue) {
		Option option = getOption(optionName, OptionType.COLOR_TYPE, defaultValue);
		try {
			return (Color) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public File getFile(String optionName, File defaultValue) {
		Option option = getOption(optionName, OptionType.FILE_TYPE, defaultValue);
		try {
			return (File) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public Font getFont(String optionName, Font defaultValue) {
		Option option = getOption(optionName, OptionType.FONT_TYPE, defaultValue);
		try {
			return (Font) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public Date getDate(String optionName, Date defaultValue) {
		Option option = getOption(optionName, OptionType.DATE_TYPE, defaultValue);
		try {
			return (Date) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public KeyStroke getKeyStroke(String optionName, KeyStroke defaultValue) {
		Option option = getOption(optionName, OptionType.KEYSTROKE_TYPE, defaultValue);
		try {
			return (KeyStroke) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public String getString(String optionName, String defaultValue) {
		Option option = getOption(optionName, OptionType.STRING_TYPE, defaultValue);
		try {
			return (String) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends Enum<T>> T getEnum(String optionName, T defaultValue) {
		Option option = getOption(optionName, OptionType.ENUM_TYPE, defaultValue);
		try {
			return (T) option.getValue(defaultValue);
		}
		catch (ClassCastException e) {
			return defaultValue;
		}
	}

	@Override
	public void setLong(String optionName, long value) {
		putObject(optionName, Long.valueOf(value), OptionType.LONG_TYPE);
	}

	@Override
	public void setBoolean(String optionName, boolean value) {
		putObject(optionName, Boolean.valueOf(value), OptionType.BOOLEAN_TYPE);
	}

	@Override
	public void setInt(String optionName, int value) {
		putObject(optionName, Integer.valueOf(value), OptionType.INT_TYPE);
	}

	@Override
	public void setDouble(String optionName, double value) {
		putObject(optionName, Double.valueOf(value), OptionType.DOUBLE_TYPE);
	}

	@Override
	public void setFloat(String optionName, float value) {
		putObject(optionName, Float.valueOf(value), OptionType.FLOAT_TYPE);
	}

	@Override
	public void setCustomOption(String optionName, CustomOption value) {
		putObject(optionName, value, OptionType.CUSTOM_TYPE);
	}

	@Override
	public void setByteArray(String optionName, byte[] value) {
		putObject(optionName, value, OptionType.BYTE_ARRAY_TYPE);
	}

	@Override
	public void setFile(String optionName, File value) {
		putObject(optionName, value, OptionType.FILE_TYPE);
	}

	@Override
	public void setColor(String optionName, Color value) {
		putObject(optionName, value, OptionType.COLOR_TYPE);
	}

	@Override
	public void setFont(String optionName, Font value) {
		putObject(optionName, value, OptionType.FONT_TYPE);
	}

	@Override
	public void setDate(String optionName, Date value) {
		putObject(optionName, value, OptionType.DATE_TYPE);
	}

	@Override
	public void setKeyStroke(String optionName, KeyStroke value) {
		putObject(optionName, value, OptionType.KEYSTROKE_TYPE);
	}

	@Override
	public void setString(String optionName, String value) {
		putObject(optionName, value, OptionType.STRING_TYPE);
	}

	@Override
	public <T extends Enum<T>> void setEnum(String optionName, T value) {
		putObject(optionName, value, OptionType.ENUM_TYPE);
	}

	@Override
	public Object getDefaultValue(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.getDefaultValue();
	}

	@Override
	public PropertyEditor getPropertyEditor(String optionName) {
		if (!SwingUtilities.isEventDispatchThread()) {
			throw new IllegalStateException("This method must be called from the swing thread.");
		}
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		PropertyEditor editor = option.getPropertyEditor();
		if (editor == null) {
			editor = findPropertyEditor(option.getOptionType().getValueClass());
		}
		return editor;
	}

	@Override
	public PropertyEditor getRegisteredPropertyEditor(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.getPropertyEditor();
	}

	@Override
	public synchronized boolean contains(String optionName) {
		return valueMap.containsKey(optionName) || aliasMap.containsKey(optionName);
	}

	@Override
	public String getDescription(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.getDescription();
	}

	@Override
	public HelpLocation getHelpLocation(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.getHelpLocation();
	}

	@Override
	public boolean isRegistered(String optionName) {
		Option option = valueMap.get(optionName);
		if (option == null) {
			return false;
		}
		return option.isRegistered();
	}

	@Override
	public boolean isDefaultValue(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		return option.isDefault();
	}

	@Override
	public void restoreDefaultValues() {
		List<String> optionNames = getOptionNames();
		for (String optionName : optionNames) {
			restoreDefaultValue(optionName);
		}
	}

	@Override
	public void restoreDefaultValue(String optionName) {
		Option option = getOption(optionName, OptionType.NO_TYPE, null);
		if (option.isDefault()) {
			return;
		}
		Object previousValue = option.getCurrentValue();
		option.restoreDefault();
		notifyOptionChanged(optionName, previousValue, option.getCurrentValue());
	}

	@Override
	public synchronized List<Options> getChildOptions() {
		Set<String> childNames = getChildCategories(getOptionNames());
		List<Options> optionsList = new ArrayList<>(childNames.size());
		for (String childName : childNames) {
			optionsList.add(new SubOptions(this, childName, childName + DELIMITER_STRING));
		}
		return optionsList;
	}

	@Override
	public Options getOptions(String path) {
		return new SubOptions(this, path, path + DELIMITER);
	}

	@Override
	public synchronized void setOptionsHelpLocation(HelpLocation helpLocation) {
		categoryHelpMap.put("", helpLocation);
	}

	@Override
	public synchronized HelpLocation getOptionsHelpLocation() {
		return categoryHelpMap.get("");
	}

	@Override
	public synchronized void registerOptionsEditor(OptionsEditor editor) {
		optionsEditorMap.put("", editor);
	}

	@Override
	public synchronized OptionsEditor getOptionsEditor() {
		return optionsEditorMap.get("");
	}

	@Override
	public synchronized void createAlias(String aliasName, Options options, String optionsName) {
		if (options instanceof SubOptions) {
			SubOptions subOptions = (SubOptions) options;
			options = subOptions.getOptions();
			optionsName = subOptions.getPrefix() + optionsName;
		}

		if (options instanceof AbstractOptions) {
			aliasMap.put(aliasName, new AliasBinding((AbstractOptions) options, optionsName));
			return;
		}
		throw new IllegalArgumentException(
			"Can only alias options that extend AbstractOptions or is a SubOptions of an AbstractOptions");
	}

	@Override
	public synchronized boolean isAlias(String aliasName) {
		return aliasMap.containsKey(aliasName);
	}

	static Set<String> getChildCategories(Collection<String> optionPaths) {
		Set<String> childNames = new HashSet<>();
		for (String path : optionPaths) {
			int index = path.indexOf(DELIMITER);
			if (index < 0) {
				continue;
			}
			childNames.add(path.substring(0, index));
		}
		return childNames;
	}

	static Set<String> getLeaves(Collection<String> optionPaths) {
		Set<String> childNames = new HashSet<>();
		for (String path : optionPaths) {
			int index = path.indexOf(DELIMITER);
			if (index < 0) {
				childNames.add(path);
			}
		}
		return childNames;
	}

	private boolean isSupportedType(Object obj) {
		if (obj instanceof byte[]) {
			return true;
		}
		if (obj instanceof Enum) {
			return true;
		}
		if (obj instanceof CustomOption) {
			return true;
		}

		return SUPPORTED_CLASSES.contains(obj.getClass());
	}

	/**
	 * Verifies that the option name does not contain consecutive delimiters.
	 * @throws IllegalArgumentException if consecutive delimiters were found
	 * in the option name
	 */
	private void validateOptionName(String optionName) {
		if (containsUnquotedText(optionName, ILLEGAL_DELIMITER)) {
			throw new IllegalArgumentException("Name cannot contain consecutive delimiters: " +
				optionName + " in Options " + name);
		}
		if (optionName.startsWith(DELIMITER_STRING)) {
			throw new IllegalArgumentException(
				"Name cannot start with a delimiter: " + optionName + " in Options " + name);
		}
		if (optionName.endsWith(DELIMITER_STRING)) {
			throw new IllegalArgumentException(
				"Name cannot end with a delimiter: " + optionName + " in Options " + name);
		}
	}

	/**
	 * Returns true if the given string is in the searchString and not between a pair of quotes.
	 * Note the character MUST NOT BE a quote.
	 * @param stringToSearch the string to search
	 * @param textToLocate the text to search for.
	 * @return true if the given text is in the searchString and not between a pair of quotes.
	 */
	private static boolean containsUnquotedText(String stringToSearch, String textToLocate) {

		StringBuffer buffer = new StringBuffer();
		boolean inQuotes = false;
		for (int i = 0; i < stringToSearch.length(); i++) {
			char c = stringToSearch.charAt(i);
			if (c == '\"') {
				inQuotes = !inQuotes;
			}
			else if (!inQuotes) {
				buffer.append(c);
			}
		}

		return (buffer.indexOf(textToLocate) != -1);
	}

	public synchronized void setCategoryHelpLocation(String categoryPath,
			HelpLocation helpLocation) {
		categoryHelpMap.put(categoryPath, helpLocation);
	}

	public synchronized HelpLocation getCategoryHelpLocation(String categoryPath) {
		return categoryHelpMap.get(categoryPath);
	}

	@Override
	public String getID(String optionName) {
		if (name.length() == 0) {
			return optionName;
		}
		return name + DELIMITER + optionName;
	}

	@Override
	public String getValueAsString(String optionName) {
		Object value = getObject(optionName, null);
		if (value == null) {
			return null;
		}
		return value.toString();
	}

	@Override
	public String getDefaultValueAsString(String optionName) {
		Object value = getDefaultValue(optionName);
		if (value == null) {
			return null;
		}
		return value.toString();
	}

	@Override
	public String toString() {
		List<String> optionNames = getOptionNames();
		TreeMap<String, Object> sortedOptionsMap = new TreeMap<>();
		for (String string : optionNames) {
			sortedOptionsMap.put(string, getObject(string, null));
		}
		return "Options: " + sortedOptionsMap.toString();
	}

	@Override
	public List<String> getLeafOptionNames() {
		Set<String> leafNames = getLeaves(getOptionNames());
		return new ArrayList<>(leafNames);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	public static class AliasBinding {
		AbstractOptions options;
		String path;

		AliasBinding(AbstractOptions options, String path) {
			this.options = options;
			this.path = path;
		}
	}

	public static PropertyEditor findPropertyEditor(Class<?> originalValueClass) {
		if (originalValueClass == null) {
			return null;
		}

		Class<?> valueClass = originalValueClass;
		while (valueClass != null) {
			//
			if (valueClass.getEnumConstants() != null) {
				// Hack Alert!: we have to put this code here to prevent the built-in EnumEditor
				//              from being used on Java 1.7.  That editor uses bad values for
				//              the display of enum values.
				PropertyEditorManager.registerEditor(originalValueClass, EnumEditor.class);
			}

			PropertyEditor editor = PropertyEditorManager.findEditor(valueClass);
			if (editor instanceof NoRegisteredEditorPropertyEditor) {
				return null; // This editor is a marker to indicate that we have already
				// looked for this editor and did not find one.
			}
			if (editor != null) {
				PropertyEditorManager.registerEditor(originalValueClass, editor.getClass());
				return editor;
			}
			valueClass = valueClass.getSuperclass();
		}
		PropertyEditorManager.registerEditor(originalValueClass,
			NoRegisteredEditorPropertyEditor.class);
		return null;

	}

}
