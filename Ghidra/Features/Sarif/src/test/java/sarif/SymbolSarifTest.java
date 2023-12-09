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
package sarif;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramDiff;

public class SymbolSarifTest extends AbstractSarifTest {

	public SymbolSarifTest() {
		super();
	}

	@Test
	public void testSymbolWhereDefault() throws Exception {
		Address addr = addr(0x200);
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addMemoryReference(addr(0x220), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			0);

		SymbolTable st = program.getSymbolTable();
		Symbol[] symbols = st.getSymbols(addr);

		st.createLabel(addr, "lamp", SourceType.USER_DEFINED);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());

		st.removeSymbolSpecial(symbols[0]);

		programDiff = readWriteCompare();
		
		differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	@Test
	public void testSymbolsWhereNoDefault() throws Exception {
		Address addr = addr(0x0200);

		SymbolTable st = program.getSymbolTable();
		st.createLabel(addr, "lamp", SourceType.USER_DEFINED);

		st.createLabel(addr, "shade", SourceType.ANALYSIS);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}
	
	@Test
	public void testSymbolsNamespace() throws Exception {
		Address addr = addr(0);

		SymbolTable st = program.getSymbolTable();
		Namespace newspace = st.createNameSpace(null, "other", SourceType.USER_DEFINED);

		st.createLabel(addr, "foo", newspace, SourceType.USER_DEFINED);

		st.createLabel(addr, "bar", SourceType.IMPORTED);
		
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
