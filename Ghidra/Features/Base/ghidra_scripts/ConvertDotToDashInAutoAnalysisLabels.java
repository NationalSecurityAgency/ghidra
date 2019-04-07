/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
// Converts the '.'s to '_'s in auto-analysis created CODE and FUNCTION labels (some case and switch statements)
// Use this script for updating pre3.2 files so that exported C code can compile
// Need to run the UpdateSymbolSourceScript first if the symbols have not been updated yet

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class ConvertDotToDashInAutoAnalysisLabels extends GhidraScript {
	@Override
    public void run() throws Exception {

		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();
		
		while(it.hasNext()) {
			Symbol s = it.next();
			String name = s.getName();		
			if(s.getSource() == SourceType.ANALYSIS && (!name.startsWith("u_")) && (!name.startsWith("s_"))){					
				String newName = name.replace('.','_');
				s.setName(newName,SourceType.ANALYSIS);					
				}
			}
		}				

}
