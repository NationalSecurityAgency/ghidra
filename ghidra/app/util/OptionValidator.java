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

import java.util.List;

/**
 * Callback interface for validating a list of options with values.
 */
public interface OptionValidator {

	/**
	 * Validates the options if valid, returns null. Otherwise an error message is returned.
	 * @param options the options to be validated.
	 * @return null, if the options have valid values.  Otherwise return an error message.
	 */
	String validateOptions(List<Option> options);
}
