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
//Script that removes single quotes from imported and analysis primary symbols only. The main 
//purpose of this script is to fix up symbols created by pdb or demangler that include the quotes 
//surrounding strings in the preprocessed name information. 
//@category Symbol
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class RemoveSymbolQuotesScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No open program");
			return;
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();

		SymbolIterator symbolIterator = symbolTable.getPrimarySymbolIterator(true);

		while (symbolIterator.hasNext()) {
			monitor.checkCancelled();

			Symbol symbol = symbolIterator.next();

			// don't mess with user created symbols
			if (symbol.getSource() == SourceType.USER_DEFINED) {
				continue;
			}
			// don't remove from default ones -- ones formed by string data might have these
			// characters
			if (symbol.getSource() == SourceType.DEFAULT) {
				continue;
			}

			String name = symbol.getName();
			name = name.replaceAll("`", "");
			name = name.replaceAll("'", "");
			symbol.setName(name, symbol.getSource());
		}
	}

}
