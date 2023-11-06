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
package docking.widgets.values;

import java.io.File;
import java.util.*;

import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.StatusListener;

/**
 * Class for defining, storing, and retrieving groups of values of various types. The intended use
 * is to create a ValuesMap, define some named values, and then invoke the ValuesMapDialog to allow
 * the user to fill in values for the defined values. It also has a rich set of convenience methods
 * for adding predefined value types to the map. Users can also directly add custom value types by
 * using the {@link #addValue(AbstractValue)} method.
 */
public class GValuesMap {

	protected Map<String, AbstractValue<?>> valuesMap = new LinkedHashMap<>();
	private ValuesMapValidator validator;

	/**
	 * Returns a collection of the AbstractValues defined in this ValuesMap.
	 * @return a collection of the AbstractValues defined in this ValuesMap.
	 */
	public Collection<AbstractValue<?>> getValues() {
		return valuesMap.values();
	}

	/**
	 * Adds an AbstractValue to this ValuesMap. This is a way to add a custom AbstractValue that
	 * doesn't have a convenience method for a predefine value type.
	 * @param value the AbstractValue to add to this ValuesMap
	 * @return returns the added value 
	 */
	public AbstractValue<?> addValue(AbstractValue<?> value) {
		String name = value.getName();
		checkDup(name);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Sets a {@link ValuesMapValidator}. If set, this will be called when the user presses the 
	 * "Ok" button on the {@link ValuesMapDialog}. If the validator passes (returns true), then 
	 * the dialog will close and return the user values. Otherwise, the dialog will display the
	 * error message (via the {@link StatusListener} in the 
	 * {@link ValuesMapValidator#validate(GValuesMap, StatusListener)} call) and remain open.
	 * @param validator the validator to be called before returning from the dialog
	 */
	public void setValidator(ValuesMapValidator validator) {
		this.validator = validator;
	}

	/**
	 * The call to validate the data using the {@link ValuesMapValidator} set in the
	 * {@link #setValidator(ValuesMapValidator)} method. If no validator has been set,
	 * this method will return true.
	 * @param listener The {@link StatusListener} for reporting an error message.
	 * @return true if the validator passes or no validator has been set.
	 */
	public boolean isValid(StatusListener listener) {
		if (validator != null) {
			return validator.validate(this, listener);
		}
		return true;
	}

	/**
	 * Updates each value in this ValuesMap from its corresponding JComponent.
	 * @throws ValuesMapParseException if any value encountered an error trying to update its
	 * value from the editor component.
	 */
	public void updateFromComponents() throws ValuesMapParseException {
		for (AbstractValue<?> inputValue : valuesMap.values()) {
			inputValue.updateValueFromComponent();
		}
	}

	/**
	 * Returns the AbstractValue for the given value name.
	 * @param name the name for which to get the AbstractValue
	 * @return the AbstractValue for the given value name.
	 */
	public AbstractValue<?> getAbstractValue(String name) {
		return valuesMap.get(name);
	}

	/**
	 * Returns true if there is a defined value for the given name.
	 * @param name the name of the value to check for
	 * @return true if there is a defined value for the given name.
	 */
	public boolean isDefined(String name) {
		return valuesMap.containsKey(name);
	}

	/**
	 * Returns true if the value defined for the given name has a non-null value.
	 * @param name the name of the value
	 * @return true if the value defined for the given name has a non-null value.
	 */
	public boolean hasValue(String name) {
		AbstractValue<?> abstractValue = valuesMap.get(name);
		if (abstractValue == null) {
			throw new IllegalArgumentException("No value defined for " + name);
		}
		return abstractValue.hasValue();
	}

	/**
	 * Copies the values (not the AbstractValues objects, but the T values of each AbstractValue)
	 * from the given map into this map. The given map must have exactly the same name and
	 * AbstractValue types as this map.
	 * @param otherMap The GValuesMap to copy values from
	 * @throws IllegalArgumentException if the given map does not have exactly the same set of
	 * names and types as this this map
	 */
	@SuppressWarnings("unchecked")
	public void copyValues(GValuesMap otherMap) {
		for (AbstractValue<?> v : valuesMap.values()) {
			AbstractValue<?> otherValue = otherMap.getAbstractValue(v.getName());
			if (otherValue == null || otherValue.getClass() != v.getClass()) {
				throw new IllegalArgumentException(
					"Can't copy values from incompatable " + getClass().getSimpleName() + "s!");
			}
			v.copyValue(v.getClass().cast(otherValue));
		}
	}

//==================================================================================================
// Define Value Methods
//==================================================================================================	

	/**
	 * Defines a value of type Boolean.
	 * @param name the name for this value
	 * @param defaultValue the default value for this boolean value.
	 * @return the new BooleanValue that was defined.
	 */
	public BooleanValue defineBoolean(String name, boolean defaultValue) {
		checkDup(name);
		BooleanValue value = new BooleanValue(name, defaultValue);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type String, but with a restricted set of valid string values.
	 * @param name the name for this value.
	 * @param defaultValue an optional (can be null) initial value
	 * @param choices varargs list of valid string choices
	 * @return the new ChoiceValue that was defined
	 */
	public ChoiceValue defineChoice(String name, String defaultValue, String... choices) {
		checkDup(name);
		ChoiceValue value = new ChoiceValue(name, defaultValue, choices);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type File, but is restricted to directories.
	 * @param name the name for this value
	 * @param defaultValue an optional initial value
	 * @return the new FileValue that was defined
	 */
	public FileValue defineDirectory(String name, File defaultValue) {
		checkDup(name);
		FileValue value =
			new FileValue(name, defaultValue, null, GhidraFileChooserMode.DIRECTORIES_ONLY);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Double with no initial default value.
	 * @param name the name for this value
	 * @return the new DoubleValue that was defined
	 */
	public DoubleValue defineDouble(String name) {
		checkDup(name);
		DoubleValue value = new DoubleValue(name, null);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Double with an initial value
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @return the new DoubleValue that was defined
	 */
	public DoubleValue defineDouble(String name, double defaultValue) {
		checkDup(name);
		DoubleValue value = new DoubleValue(name, defaultValue);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type File
	 * @param name the name for this value
	 * @param defaultValue an optional initial value
	 * @return the new FileValue that was defined
	 */
	public FileValue defineFile(String name, File defaultValue) {
		return defineFile(name, defaultValue, null);
	}

	/**
	 * Defines a value of type File
	 * @param name the name for this value
	 * @param defaultValue an optional initial value
	 * @param startingDir specifies the starting directory when the FileChooser is invoked
	 * @return the new FileValue that was defined
	 */
	public FileValue defineFile(String name, File defaultValue, File startingDir) {
		checkDup(name);
		FileValue value =
			new FileValue(name, defaultValue, startingDir, GhidraFileChooserMode.FILES_ONLY);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Integer that displays as a hex value.
	 * @param name the name for this value
	 * @return the new IntValue that was defined
	 */
	public IntValue defineHexInt(String name) {
		checkDup(name);
		IntValue value = new IntValue(name, null, true);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Integer with an initial value and displays as a hex value.
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @return the new IntValue that was defined
	 */
	public IntValue defineHexInt(String name, int defaultValue) {
		checkDup(name);
		IntValue value = new IntValue(name, defaultValue, true);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Long that displays as a hex value.
	 * @param name the name for this value
	 * @return the new LongValue that was defined
	 */
	public LongValue defineHexLong(String name) {
		checkDup(name);
		LongValue value = new LongValue(name, null, true);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Long with an initial value and displays as a hex value.
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @return the new LongValue that was defined
	 */
	public LongValue defineHexLong(String name, long defaultValue) {
		checkDup(name);
		LongValue value = new LongValue(name, defaultValue, true);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Integer with no initial value.
	 * @param name the name for this value
	 * @return the new IntValue that was defined
	 */
	public IntValue defineInt(String name) {
		checkDup(name);
		IntValue value = new IntValue(name, null, false);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Integer with an initial value.
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @return the new IntValue that was defined
	 */
	public IntValue defineInt(String name, int defaultValue) {
		checkDup(name);
		IntValue value = new IntValue(name, defaultValue, false);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Long with an initial value.
	 * @param name the name for this value
	 * @return the new LongValue that was defined
	 */
	public LongValue defineLong(String name) {
		checkDup(name);
		LongValue value = new LongValue(name, null, false);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Long with an initial value.
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @return the new LongValue that was defined
	 */
	public LongValue defineLong(String name, long defaultValue) {
		checkDup(name);
		LongValue value = new LongValue(name, defaultValue, false);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type String.
	 * @param name the name for this value
	 * @return the new StringValue that was defined
	 */
	public StringValue defineString(String name) {
		checkDup(name);
		StringValue value = new StringValue(name, null);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type String with an optional initial value
	 * @param name the name for this value
	 * @param defaultValue the initial value (can be null)
	 * @return the new StringValue that was defined
	 */
	public StringValue defineString(String name, String defaultValue) {
		checkDup(name);
		StringValue value = new StringValue(name, defaultValue);
		valuesMap.put(name, value);
		return value;
	}

//==================================================================================================
// Get Value Methods
//==================================================================================================	

	/**
	 * Gets the boolean value for the given name.
	 * @param name the name of a previously defined boolean value
	 * @return the boolean value
	 * @throws IllegalArgumentException if the name hasn't been defined as a boolean type
	 */
	public boolean getBoolean(String name) {
		BooleanValue booleanValue = getValue(name, BooleanValue.class, "Boolean");
		Boolean value = booleanValue.getValue();
		return value == null ? false : value;
	}

	/**
	 * Gets the Choice (String) value for the given name. The value will be either null or one of
	 * the strings that were defined as valid choices.
	 * @param name the name of a previously defined Choice value
	 * @return the Choice value
	 * @throws IllegalArgumentException if the name hasn't been defined as a Choice type
	 */
	public String getChoice(String name) {
		ChoiceValue choiceValue = getValue(name, ChoiceValue.class, "Choice");
		return choiceValue.getValue();
	}

	/**
	 * Gets the double value for the given name.
	 * @param name the name of a previously defined double value
	 * @return the double value
	 * @throws IllegalArgumentException if the name hasn't been defined as a double type
	 */
	public double getDouble(String name) {
		DoubleValue doubleValue = getValue(name, DoubleValue.class, "Double");
		Double value = doubleValue.getValue();
		return value == null ? 0.0 : value;
	}

	/**
	 * Gets the {@link File} value for the given name.
	 * @param name the name of a previously defined File value
	 * @return the File value
	 * @throws IllegalArgumentException if the name hasn't been defined as a File type
	 */
	public File getFile(String name) {
		FileValue fileValue = getValue(name, FileValue.class, "File");
		return fileValue.getValue();
	}

	/**
	 * Gets the int value for the given name.
	 * @param name the name of a previously defined int value
	 * @return the int value
	 * @throws IllegalArgumentException if the name hasn't been defined as a int type
	 */
	public int getInt(String name) {
		IntValue intValue = getValue(name, IntValue.class, "Int");
		Integer value = intValue.getValue();
		return value == null ? 0 : value;

	}

	/**
	 * Gets the long value for the given name.
	 * @param name the name of a previously defined long value
	 * @return the long value
	 * @throws IllegalArgumentException if the name hasn't been defined as a long type
	 */
	public long getLong(String name) {
		LongValue longValue = getValue(name, LongValue.class, "Int");
		Long value = longValue.getValue();
		return value == null ? 0 : value;
	}

	/**
	 * Gets the String value for the given name.
	 * @param name the name of a previously defined String value
	 * @return the String value
	 * @throws IllegalArgumentException if the name hasn't been defined as a String type
	 */
	public String getString(String name) {
		StringValue stringValue = getValue(name, StringValue.class, "String");
		return stringValue.getValue();
	}

//==================================================================================================
// Set Value Methods
//==================================================================================================	

	/**
	 * Sets the boolean value for the given name.
	 * @param name the name of the boolean value that was previously defined
	 * @param value the boolean to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a boolean type
	 */
	public void setBoolean(String name, boolean value) {
		BooleanValue booleanValue = getValue(name, BooleanValue.class, "Boolean");
		booleanValue.setValue(value);
	}

	/**
	 * Sets the Choice (String) value for the given name. 
	 * @param name the name of the Choice value that was previously defined
	 * @param choice the string to set as the value. This String must be one of the defined choices
	 * @throws IllegalArgumentException if the name hasn't been defined as a choice type
	 */
	public void setChoice(String name, String choice) {
		ChoiceValue choiceValue = getValue(name, ChoiceValue.class, "Choice");
		choiceValue.setValue(choice);
	}

	/**
	 * Sets the double value for the given name.
	 * @param name the name of the double value that was previously defined
	 * @param value the double to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a double type
	 */
	public void setDouble(String name, double value) {
		DoubleValue doubleValue = getValue(name, DoubleValue.class, "Double");
		doubleValue.setValue(value);
	}

	/**
	 * Sets the {@link File} value for the given name.
	 * @param name the name of the File value that was previously defined
	 * @param value the File to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a File type
	 */
	public void setFile(String name, File value) {
		FileValue fileValue = getValue(name, FileValue.class, "File");
		fileValue.setValue(value);
	}

	/**
	 * Sets the int value for the given name.
	 * @param name the name of the int value that was previously defined
	 * @param value the int to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a int type
	 */
	public void setInt(String name, int value) {
		IntValue intValue = getValue(name, IntValue.class, "Int");
		intValue.setValue(value);
	}

	/**
	 * Sets the long value for the given name.
	 * @param name the name of the long value that was previously defined
	 * @param value the long to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a long type
	 */
	public void setLong(String name, long value) {
		LongValue intValue = getValue(name, LongValue.class, "Long");
		intValue.setValue(value);
	}

	/**
	 * Sets the String value for the given name.
	 * @param name the name of the String value that was previously defined
	 * @param value the String to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a String type
	 */
	public void setString(String name, String value) {
		StringValue stringValue = getValue(name, StringValue.class, "String");
		stringValue.setValue(value);
	}

//==================================================================================================
// Protected Methods
//==================================================================================================	

	@SuppressWarnings("unchecked")
	protected <T> T getValue(String name, Class<T> c, String typeName) {
		AbstractValue<?> value = valuesMap.get(name);
		if (value == null) {
			throw new IllegalArgumentException("No value defined for " + name);
		}
		if (value.getClass().isAssignableFrom(c)) {
			return (T) value;
		}
		throw new IllegalArgumentException(
			"Wrong type! No " + typeName + " value defined for: " + name);
	}

	protected void checkDup(String name) {
		if (valuesMap.containsKey(name)) {
			throw new IllegalArgumentException("value already exits named " + name);
		}
	}

	/**
	 * Resets the values back to their original values when constructed. Used by the dialog
	 * when the user cancels.
	 */
	protected void reset() {
		for (AbstractValue<?> inputValue : valuesMap.values()) {
			inputValue.reset();
		}
	}

}
