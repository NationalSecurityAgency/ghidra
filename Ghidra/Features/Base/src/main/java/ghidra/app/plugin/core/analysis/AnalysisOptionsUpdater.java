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
package ghidra.app.plugin.core.analysis;

import java.util.*;
import java.util.function.Function;

import ghidra.framework.options.Options;

/**
 * An object that allows analyzers to rename options.   This is required to move old options stored
 * in the program to the new equivalent option.   This class is not required for options that have
 * simply been removed.
 * <p>
 * Notes:
 * <ul>
 * 	<li>
 *  Replacement options must be registered with one of the register methods of this class.
 *  </li>
 *  <li>
 *  This is intended for use with the UI;  access analysis options from the API will not use this
 *  replacer.  This means that any client, such as script, retrieving the old option value will not
 *  work for new programs that no longer have that old option registered.  Further, for programs 
 *  that have the old options saved, but no longer registered, changing the old option value will
 *  have no effect.
 *  </li>
 *  <li>
 *  Old option values will only be used if they are non-default and the new option value is default.
 *  </li>
 *  <li>
 *  Clients can change the type of the option if they wish using 
 *  {@link #registerReplacement(String, String, Function)}.
 *  </li>
 * </ul>  
 */
public class AnalysisOptionsUpdater {

	private static final Function<Object, Object> OLD_VALUE_REPLACER = oldValue -> oldValue;

	private Map<String, ReplaceableOption> optionsByNewName = new HashMap<>();

	/**
	 * Register the given old option name to be replaced with the new option name.  The 
	 * replacement strategy used in this case will be to return the old value for the new option.
	 * @param newOptionName the new option name
	 * @param oldOptionName the old option name
	 */
	public void registerReplacement(String newOptionName, String oldOptionName) {

		registerReplacement(newOptionName, oldOptionName, OLD_VALUE_REPLACER);
	}

	/**
	 * Register the given old option name to be replaced with the new option name.  The given 
	 * replacer function will be called with the old option value to get the new option value.
	 * @param newOptionName the new option name
	 * @param oldOptionName the old option name
	 * @param replacer the function to update the update the old option value
	 */
	public void registerReplacement(String newOptionName, String oldOptionName,
			Function<Object, Object> replacer) {

		optionsByNewName.put(newOptionName,
			new ReplaceableOption(newOptionName, oldOptionName, replacer));
	}

	Set<ReplaceableOption> getReplaceableOptions() {
		return new HashSet<>(optionsByNewName.values());
	}

	/**
	 * A simple object that contains the new and old option name along with the replacer function 
	 * that will handle the option replacement.
	 */
	public static class ReplaceableOption {

		private final String newName;
		private final String oldName;
		private final Function<Object, Object> replacer;

		ReplaceableOption(String newName, String oldName, Function<Object, Object> replacer) {
			this.newName = newName;
			this.oldName = oldName;
			this.replacer = replacer;
		}

		// note: this method expects to be called within a transaction
		void replace(Options options) {
			Object oldValue = options.getObject(oldName, null);
			if (oldValue == null) {
				return;
			}

			if (options.isDefaultValue(oldName)) {
				return;
			}

			if (!options.isDefaultValue(newName)) {
				return; // don't overwrite user's updated value
			}

			Object newValue = replacer.apply(oldValue);
			options.putObject(newName, newValue);
		}

		String getNewName() {
			return newName;
		}

		String getOldName() {
			return oldName;
		}
	}
}
