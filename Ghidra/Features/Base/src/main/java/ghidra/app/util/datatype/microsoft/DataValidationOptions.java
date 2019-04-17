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
package ghidra.app.util.datatype.microsoft;

/**
 * Holds options for controlling how validation is performed when determining whether or not to 
 * create data structures at a particular location.
 */
public class DataValidationOptions {

	private boolean validateReferredToData = true;
	private boolean ignoreInstructions = false;
	private boolean ignoreDefinedData = true;

	/**
	 * Creates a DataValidationOptions object with the default values.
	 */
	public DataValidationOptions() {
	}

	/**
	 * Copy constructor
	 * @param validationOptions the data validation options to copy
	 */
	public DataValidationOptions(DataValidationOptions validationOptions) {
		validateReferredToData = validationOptions.validateReferredToData;
		ignoreInstructions = validationOptions.ignoreInstructions;
		ignoreDefinedData = validationOptions.ignoreDefinedData;
	}

	/**
	 * An option indicating whether or not to follow references to other data and validate those too.
	 * If this is set to true then the data is only valid if its referred to data is also valid.
	 * <br>Default is true.
	 * @return true if structures should be validated for referred to data.
	 */
	public boolean shouldValidateReferredToData() {
		return validateReferredToData;
	}

	/**
	 * Sets whether or not to validate follow on data that is referred to by the current 
	 * new structure.
	 * @param validateReferredToData true indicates follow on data should be validated.
	 */
	public void setValidateReferredToData(boolean validateReferredToData) {
		this.validateReferredToData = validateReferredToData;
	}

	/**
	 * An option indicating whether or not existing instructions should make the location invalid 
	 * for new data.
	 * <br>Default is false.
	 * @return false if existing instructions should cause the creation of new data to be invalid.
	 */
	public boolean shouldIgnoreInstructions() {
		return ignoreInstructions;
	}

	/**
	 * Sets whether or not existing instructions should invalidate the creation of new data.
	 * @param ignoreInstructions false indicates existing instructions, where the data would be 
	 * created, should cause validation to fail.
	 */
	public void setIgnoreInstructions(boolean ignoreInstructions) {
		this.ignoreInstructions = ignoreInstructions;
	}

	/**
	 * An option indicating whether or not existing defined data should make the location invalid 
	 * for new data.
	 * <br>Default is true.
	 * @return false if existing defined data should cause the creation of new data to be invalid.
	 */
	public boolean shouldIgnoreDefinedData() {
		return ignoreDefinedData;
	}

	/**
	 * Sets whether or not existing defined data should invalidate the creation of new data.
	 * @param ignoreDefinedData false indicates existing defined data, where the data would be 
	 * created, should cause validation to fail.
	 */
	public void setIgnoreDefinedData(boolean ignoreDefinedData) {
		this.ignoreDefinedData = ignoreDefinedData;
	}
}
