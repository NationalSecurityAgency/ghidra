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
package ghidra.trace.model.symbol;

import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * The class symbol view.
 */
public interface TraceClassSymbolView extends TraceSymbolNoDuplicatesView<TraceClassSymbol> {
	/**
	 * Add a new class symbol.
	 * 
	 * @param name the name of the class
	 * @param parent the parent namespace
	 * @param source the source
	 * @return the new class symbol
	 * @throws DuplicateNameException if the name is duplicated in the parent namespace
	 * @throws InvalidInputException if the name is not valid
	 * @throws IllegalArgumentException if some other argument is not valid
	 */
	TraceClassSymbol add(String name, TraceNamespaceSymbol parent, SourceType source)
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException;
}
