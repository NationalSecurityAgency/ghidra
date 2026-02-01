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

/**
 * Exception thrown when processing/parsing ValuesMap values. Mostly exists so that the exception
 * message is uniform throught the types.
 */
public class ValuesMapParseException extends Exception {

	/**
	 * Constructor
	 * @param valueName the name of the value that was being processed
	 * @param type the type name of the value that was being processed
	 * @param message the detail message of what went wrong
	 */
	public ValuesMapParseException(String valueName, String type, String message) {
		super("Error processing " + type + " value \"" + valueName + "\"! " + message);
	}
}
