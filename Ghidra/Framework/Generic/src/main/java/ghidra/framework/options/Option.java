/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

import java.beans.PropertyEditor;

public abstract class Option {
	private final String name;
	private final Object defaultValue;
	private boolean isRegistered;
	private final String description;
	private final HelpLocation helpLocation;
	private final OptionType optionType;

	private final PropertyEditor propertyEditor;
	private String inceptionInformation;

	protected Option(String name, OptionType optionType, String description,
			HelpLocation helpLocation, Object defaultValue, boolean isRegistered,
			PropertyEditor editor) {
		this.name = name;
		this.optionType = optionType;
		this.description = description;
		this.helpLocation = helpLocation;
		this.defaultValue = defaultValue;
		this.isRegistered = isRegistered;
		this.propertyEditor = editor;
		if (!isRegistered) {
			recordInception();
		}
	}

	public abstract Object getCurrentValue();

	public abstract void doSetCurrentValue(Object value);

	public void setCurrentValue(Object value) {
		this.isRegistered = true;
		doSetCurrentValue(value);
	}

	public String getName() {
		return name;
	}

	public PropertyEditor getPropertyEditor() {
		return propertyEditor;
	}

	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	public boolean hasValue() {
		return defaultValue != null || getCurrentValue() != null;
	}

	public String getDescription() {
		return description == null ? "Unregistered Option" : description;
	}

	public Object getValue(Object passedInDefaultValue) {
		Object value = getCurrentValue();
		if (value != null) {
			return value;
		}
		if (defaultValue != null) {
			return defaultValue;
		}
		return passedInDefaultValue;
	}

	public boolean isRegistered() {
		return isRegistered;
	}

	public void restoreDefault() {
		setCurrentValue(defaultValue);
	}

	public boolean isDefault() {
		Object value = getCurrentValue();
		if (value == null) {
			return true;
		}

		return value.equals(defaultValue);
	}

	@Override
	public String toString() {
		return "[current value=" + getCurrentValue() + ", default value=" + defaultValue +
			", isRegistered=" + isRegistered + "]";
	}

	public Object getDefaultValue() {
		return defaultValue;
	}

	public String getInceptionInformation() {
		return inceptionInformation;
	}

	private void recordInception() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			return;
		}
		Throwable throwable = new Throwable();
		StackTraceElement[] stackTrace = throwable.getStackTrace();

		String information = getInceptionInformationFromTheFirstClassThatIsNotUs(stackTrace);
		inceptionInformation = information;
	}

	private String getInceptionInformationFromTheFirstClassThatIsNotUs(
			StackTraceElement[] stackTrace) {

		// To find our creation point we can use a simple algorithm: find the name of our class, 
		// which is in the first stack trace element and then keep walking backwards until that
		// name is not ours.
		//         
		String myClassName = getClass().getName();
		int myClassNameStartIndex = -1;
		for (int i = 1; i < stackTrace.length; i++) { // start at 1, because we are the first item
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();
			if (myClassName.equals(elementClassName)) {
				myClassNameStartIndex = i;
				break;
			}
		}

		// Finally, go backwards until we find a non-options class in the stack, in order
		// to remove infrastructure code from the client that called the options API.
		int creatorIndex = myClassNameStartIndex;
		for (int i = myClassNameStartIndex; i < stackTrace.length; i++) { // start at 1, because we are the first item
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();

			if (elementClassName.toLowerCase().indexOf("option") == -1) {
				creatorIndex = i;
				break;
			}
		}

		return stackTrace[creatorIndex].toString();
	}

	public OptionType getOptionType() {
		return optionType;
	}

}
