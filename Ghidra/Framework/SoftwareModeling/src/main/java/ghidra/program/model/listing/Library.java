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
package ghidra.program.model.listing;

import ghidra.program.model.symbol.*;

/**
 * Interface for a Library namespace.
 */
public interface Library extends Namespace {

	public static final String UNKNOWN = "<EXTERNAL>";

	@Override
	public default Type getType() {
		return Type.LIBRARY;
	}

	/**
	 * @return the associated program within the project which corresponds to this library
	 */
	public String getAssociatedProgramPath();

	/**
	 * Get the Library which contains the specified external symbol.
	 * @param symbol external symbol
	 * @return null if symbol is null or not external
	 */
	public static Library getContainingLibrary(Symbol symbol) {
		if (symbol == null) {
			return null;
		}
		if (symbol.getSymbolType() == SymbolType.LIBRARY) {
			return (Library) symbol.getObject();
		}
		if (symbol.getSymbolType() == SymbolType.NAMESPACE ||
			symbol.getSymbolType() == SymbolType.CLASS) {
			while (symbol != null && symbol.isExternal()) {
				Namespace n = (Namespace) symbol.getObject();
				if (n instanceof Library lib) {
					return lib;
				}
				symbol = n.getParentNamespace().getSymbol();
			}
		}
		return null;
	}

}
