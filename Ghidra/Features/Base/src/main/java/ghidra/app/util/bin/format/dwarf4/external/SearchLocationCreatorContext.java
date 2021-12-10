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
package ghidra.app.util.bin.format.dwarf4.external;

import ghidra.program.model.listing.Program;

/**
 * Information outside of a location string that might be needed to create a new {@link SearchLocation}
 * instance.
 */
public class SearchLocationCreatorContext {
	private final SearchLocationRegistry registry;
	private final Program program;

	/**
	 * Create a new context object with references to the registry and the current program.
	 * 
	 * @param registry {@link SearchLocationRegistry}
	 * @param program the current {@link Program}
	 */
	public SearchLocationCreatorContext(SearchLocationRegistry registry, Program program) {
		this.registry = registry;
		this.program = program;
	}

	/**
	 * @return the {@link SearchLocationRegistry} that is creating the {@link SearchLocation}
	 */
	public SearchLocationRegistry getRegistry() {
		return registry;
	}

	/**
	 * @return the current {@link Program}
	 */
	public Program getProgram() {
		return program;
	}
}
