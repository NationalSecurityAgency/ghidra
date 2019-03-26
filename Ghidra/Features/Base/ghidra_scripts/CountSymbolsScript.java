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
//Counts the symbols in the current program and prints the total.
//@category Symbol

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class CountSymbolsScript extends GhidraScript {

    /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() {
        monitor.setMessage("Counting symbols...");
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        int count = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            if (sym != null) {
                println(sym.getName());
                count++;
            }
        }
        println(count+" symbols");
    }
}
