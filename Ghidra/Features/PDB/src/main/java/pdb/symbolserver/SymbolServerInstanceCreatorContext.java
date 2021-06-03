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
package pdb.symbolserver;

import java.io.File;

/**
 * Context for the {@link SymbolServerInstanceCreatorRegistry} when creating new
 * {@link SymbolServer} instances.
 * <p>
 * This allows the method that is creating a new SymbolServer to know the location the
 * Ghidra program was imported from, as well as to reach back to the registry itself and
 * use it to create other SymbolServer instances (if necessary).
 * <p>
 * Created via {@link SymbolServerInstanceCreatorRegistry#getContext()} or 
 * {@link SymbolServerInstanceCreatorRegistry#getContext(ghidra.program.model.listing.Program)}
 */
public class SymbolServerInstanceCreatorContext {
	private final File rootDir;
	private final SymbolServerInstanceCreatorRegistry symbolServerInstanceCreatorRegistry;

	SymbolServerInstanceCreatorContext(
			SymbolServerInstanceCreatorRegistry symbolServerInstanceCreatorRegistry) {
		this(null, symbolServerInstanceCreatorRegistry);
	}

	SymbolServerInstanceCreatorContext(File rootDir,
			SymbolServerInstanceCreatorRegistry symbolServerInstanceCreatorRegistry) {
		this.rootDir = rootDir;
		this.symbolServerInstanceCreatorRegistry = symbolServerInstanceCreatorRegistry;
	}

	/**
	 * The {@link SymbolServerInstanceCreatorRegistry} associated with this context.
	 * 
	 * @return the {@link SymbolServerInstanceCreatorRegistry}
	 */
	public SymbolServerInstanceCreatorRegistry getSymbolServerInstanceCreatorRegistry() {
		return symbolServerInstanceCreatorRegistry;
	}

	/**
	 * The root directory of the imported binary.
	 * 
	 * @return directory of the binary, or null if no associated program
	 */
	public File getRootDir() {
		return rootDir;
	}

}
