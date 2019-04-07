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
//Creates a selection in the current program consisting of the sum 
//of all function bodies.
//@category Selection

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;

public class SelectFunctionsScript extends GhidraScript {
    @Override
    public void run() {
        monitor.setMessage("Selecting functions...");
        AddressSet set = new AddressSet();
        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator iter = listing.getFunctions(true);
        int functionCount = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            functionCount++;
            Function f = iter.next();
            set.add(f.getBody());
            println("Function Entry: "+f.getEntryPoint());
        }
        println("Function Count: "+functionCount);
        createSelection(set);
    }
}
