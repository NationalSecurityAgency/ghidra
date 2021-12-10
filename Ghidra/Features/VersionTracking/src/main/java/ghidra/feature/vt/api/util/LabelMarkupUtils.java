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
package ghidra.feature.vt.api.util;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class LabelMarkupUtils {

	public static void removeAllLabels(Program destinationProgram, Address address) {
		SymbolTable symbolTable = destinationProgram.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol instanceof FunctionSymbol) {
				continue;
			}
			symbolTable.removeSymbolSpecial(symbol);
		}
	}

}
