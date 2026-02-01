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

import java.util.Objects;

import javax.swing.JComponent;

/**
 * Abstract base class for defined name/values in a {@link GValuesMap} and whose values can be
 * edited in the {@link ValuesMapDialog}. Its main purpose is to provide a JComponent for
 * editing the value. Generally, objects of this type can be in one of two states: having a value
 * or not. This can be useful for validating the dialog input values to ensure the user enters
 * a value.
 * <P>
 * There are two situations where parse/conversion exceptions can occur in subclass implementations.
 * One is the {@link #setAsText(String)} method. The subclass should catch any specific  expected 
 * exception when parsing the string and convert it to an IllegalArgumentException. The other method
 * is the {@link #updateValueFromComponent()} method which may also need to parse string data. In 
 * this case any expected exception should be converted to {@link ValuesMapParseException}. This 
 * is the only exception type the dialog will be trapping and displaying error messages for in the 
 * {@link ValuesMapDialog}. Any other type of exception will be considered unexpected and a
 * programing error and will be eventally be handled by the default application error handler.
 *
 * @param <T> The type of the value stored and edited by this class
 */
public abstract class AbstractValue<T> {
	private final String name;
	private T value;
	private T originalValue;

	/**
	 * Constructor that assigned a name and optional initial value for this object.
	 * @param name the name associated with this value.
	 * @param defaultValue an optional initial value for this object
	 */
	protected AbstractValue(String name, T defaultValue) {
		this.name = Objects.requireNonNull(name);
		this.value = defaultValue;
		this.originalValue = defaultValue;
	}

	/**
	 * Returns the name of this value object.
	 * @return the name of this value object
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the value currently assigned to this object.
	 * @return the value currently assigned to this object (may be null)
	 */
	public T getValue() {
		return value;
	}

	/**
	 * Sets the value for this object.
	 * @param value the value to set for this object (may be null)
	 */
	public void setValue(T value) {
		this.value = value;
	}

	/**
	 * Copies the T value from the given AbstractValue to this AbstractValue.
	 * @param other the AbstractValue to copy from
	 */
	public void copyValue(AbstractValue<T> other) {
		setValue(other.getValue());
	}

	/**
	 * Returns true if the value is non-null.
	 * @return true if the value is non-null
	 */
	public boolean hasValue() {
		return value != null;
	}

	/**
	 * Sets the value for this object from the given string. If this object can not succesfully
	 * parse the string, an exception will be thrown.
	 * @param valueString the string to be parsed into the type for this object
	 * @return The value resulting from parsing the string value
	 * @throws IllegalArgumentException if the string can not be parsed into a value of type T
	 */
	public T setAsText(String valueString) {
		if (valueString == null) {
			throw new IllegalArgumentException("Value string can not be null!");
		}
		value = fromString(valueString);
		return value;
	}

	/**
	 * Returns a string representation for the value. It is expected that the string returned
	 * from this method can be parsed by the corresponding {@link #setAsText(String)} method. If the
	 * value of this object is null, null will be returned.
	 * @return a string representation for the value or null if the value is null
	 */
	public String getAsText() {
		return value == null ? null : toString(value);
	}

	/**
	 * Resets the value to its original value when constructed
	 */
	protected void reset() {
		value = originalValue;
	}

	protected String toString(T t) {
		return t.toString();
	}

	/**
	 * Returns a JComponent for entering or editing a value of this type.
	 * @return a JComponent for entering or editing a value of this type.
	 */
	public abstract JComponent getComponent();

	/**
	 * Causes the stored value for this object to be updated based on the state of the 
	 * JComponent returned from {@link #getComponent()}
	 * @throws ValuesMapParseException if an error occurs trying update the value from a 
	 * component. This usually is a result of trying to parse a string value.
	 */
	protected abstract void updateValueFromComponent() throws ValuesMapParseException;

	/**
	 * Updates the JComponent returned from {@link #getComponent()} to represent the current
	 * value of this object.
	 */
	protected abstract void updateComponentFromValue();

	/**
	 * Parses the given string into a value of type T
	 * @param valueString the string to parse
	 * @return a value of type T
	 */
	protected abstract T fromString(String valueString);

}
