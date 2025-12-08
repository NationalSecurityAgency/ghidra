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

/**
 * Chooses which {@link Loader} options to use 
 * 
 * @deprecated Use {@link ProgramLoader.Builder#loaderArgs(List)} instead
 */
@Deprecated(since = "12.0", forRemoval = true)
@FunctionalInterface
public interface OptionChooser {
	public static final OptionChooser DEFAULT_OPTIONS = (choices, addressFactory) -> choices;

	/**
	 * Chooses which {@link Loader} options to use 
	 * 
	 * @param optionChoices A {@link List} of available {@link Loader} options
	 * @param addressFactory The address factory
	 * @return The {@link List} of {@link Loader} options to use
	 * @deprecated Use {@link ProgramLoader.Builder#loaderArgs(List)} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	List<Option> choose(List<Option> optionChoices, AddressFactory addressFactory);

	/**
	 * Gets the {@link Loader} arguments associated with this {@link OptionChooser}
	 * 
	 * @return The {@link Loader} arguments associated with this {@link OptionChooser}
	 * @throws UnsupportedOperationException if a subclass has not implemented this method
	 * @deprecated Use {@link ProgramLoader.Builder#loaderArgs(List)} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public default List<Pair<String, String>> getArgs() {
		throw new UnsupportedOperationException();
	}
}
