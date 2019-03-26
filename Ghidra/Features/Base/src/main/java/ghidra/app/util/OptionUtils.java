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
 * Utility class for providing convenience methods for working with {@link Option}'s.
 */
public class OptionUtils {

	/**
	 * Checks to see whether or not the given list of options contains the given option name.
	 * 
	 * @param optionName The name of the option to check.
	 * @param options A list of the all the options.
	 * @return True if the given list contains the given option; otherwise, false.
	 */
	public static boolean containsOption(String optionName, List<Option> options) {
		return options.stream().anyMatch(o -> o.getName().equals(optionName));
	}

	/**
	 * Gets the value of the option with the given name from the given list of options.
	 * 
	 * @param optionName The name of the option to get.
	 * @param options The list of options to get the option from.
	 * @param defaultValue A default option value to use if the option name was not found.
	 * @return The value of the option with the given name, or the default value if it was not 
	 *   found.
	 */
	@SuppressWarnings("unchecked")
	public static <T> T getOption(String optionName, List<Option> options, T defaultValue) {
		if (options != null) {
			for (Option option : options) {
				if (option.getName().equals(optionName)) {
					return (T) option.getValue();
				}
			}
		}
		return defaultValue;
	}

	/**
	 * Gets the boolean value of the option with the given name from the given list of options.
	 * 
	 * @param optionName The name of the boolean option to get.
	 * @param options The list of options to get the option from.
	 * @param defaultValue A default option value to use if the option name was not found.
	 * @return The boolean value of the option with the given name, or the default value if it was 
	 *   not found as a boolean option.
	 */
	public static boolean getBooleanOptionValue(String optionName, List<Option> options,
			boolean defaultValue) {

		if (options != null) {
			for (Option option : options) {
				if (option.getName().equals(optionName)) {
					Object val = option.getValue();
					if (val instanceof Boolean) {
						return (Boolean) option.getValue();
					}
				}
			}
		}
		return defaultValue;
	}
}
