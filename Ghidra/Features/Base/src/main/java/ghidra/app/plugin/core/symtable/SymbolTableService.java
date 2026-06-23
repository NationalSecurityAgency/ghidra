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
package ghidra.app.plugin.core.symtable;

import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.program.model.listing.CodeUnit;

/**
 * Service for showing {@link Symbol}s in a table.
 */
public interface SymbolTableService {

	/**
	 * Shows all symbols and offcut symbols contained in the given code unit.
	 * @param codeUnit the code unit
	 * @return the table provider that is shown
	 */
	public TableComponentProvider<SymbolRowObject> showSymbols(CodeUnit codeUnit);
}
