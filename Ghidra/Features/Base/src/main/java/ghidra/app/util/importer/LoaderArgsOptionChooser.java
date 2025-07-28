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
package ghidra.app.util.importer;

import java.util.List;

import generic.stl.Pair;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.Msg;

/**
 * An option chooser that applies loader options that were passed in as command line arguments.
 * 
 * @deprecated Use {@link ProgramLoader.Builder#loaderArgs(List)} instead
 */
@Deprecated(since = "12.0", forRemoval = true)
public class LoaderArgsOptionChooser implements OptionChooser {

	private List<Pair<String, String>> loaderArgs;

	/**
	 * Creates a new {@link LoaderArgsOptionChooser}
	 * 
	 * @param loaderArgs The {@link Loader} arguments
	 * @deprecated Use {@link ProgramLoader.Builder#loaderArgs(List)} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public LoaderArgsOptionChooser(List<Pair<String, String>> loaderArgs) {
		this.loaderArgs = loaderArgs;
	}

	@Override
	public List<Option> choose(List<Option> optionChoices, AddressFactory addressFactory) {
		if (loaderArgs != null) {
			for (Pair<String, String> pair : loaderArgs) {
				String arg = pair.first, val = pair.second;
				boolean foundIt = false;
				for (Option option : optionChoices) {
					if (option.getArg() != null && arg.equalsIgnoreCase(option.getArg())) {
						Object oldVal = option.getValue();
						if (option.parseAndSetValueByType(val, addressFactory)) {
							Msg.info(LoaderArgsOptionChooser.class, String.format(
								"Successfully applied \"%s\" to \"%s\" (old: \"%s\", new: \"%s\")",
									arg, option.getName(), oldVal, val));
						}
						else {
							Msg.error(LoaderArgsOptionChooser.class, String.format(
								"Failed to apply \"%s\" to \"%s\" (old: \"%s\", bad: \"%s\")", arg,
								option.getName(), oldVal, val));
							return null;
						}
						foundIt = true;
						break;
					}
				}
				if (!foundIt) {
					Msg.warn(LoaderArgsOptionChooser.class,
						"Skipping unsupported " + arg + " argument");
				}
			}
		}
		return optionChoices;
	}

	@Override
	public List<Pair<String, String>> getArgs() {
		return loaderArgs;
	}
}
