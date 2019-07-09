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
//For an 8051 program, changes source of labels in SFR, BITS, and SFR-BITS address spaces to be 
// "imported."
//@category Update

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class Update8051 extends GhidraScript {

	private final static String SFR = "SFR";
	private final static String BITS = "BITS";
	private final static String SFR_BITS = "SFR-BITS";
	
    @Override
    public void run() throws Exception {
    	if (currentProgram.getAddressFactory().getNumAddressSpaces() == 1) {
    		println("Program is not an 8051");
    		return;
    	}
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator iter = st.getDefinedSymbols();
		int count = 0;
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			String spaceName = symbol.getAddress().getAddressSpace().getName();
			if (spaceName.equals(SFR) || spaceName.equals(BITS) || spaceName.equals(SFR_BITS)) {
				symbol.setSource(SourceType.IMPORTED);
				println("Changed source on " + symbol.getName());
				++count;
			}
		}
		if (count == 0) {
			println("No address spaces found for " +SFR + ", "+ BITS + ", " + SFR_BITS + ".");
		}
		else {
			String str = (count > 1 ? " symbols to update." : " symbol to update."); 
			println("Found " + count + str);
		}
    }

}
