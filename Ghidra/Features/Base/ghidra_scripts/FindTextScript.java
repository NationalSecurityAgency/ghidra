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
//Prompts the user for a search string and searches the 
//program listing for the first occurrence of that string.
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class FindTextScript extends GhidraScript {

    /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws Exception {
		if (currentAddress == null) {
			println("NO CURRENT ADDRESS");
			return;
		}
		if (currentProgram == null) {
			println("NO CURRENT PROGRAM");
			return;
		}
        String search = askString("Text Search", "Enter search string: ");
        Address addr = find(search);
        if (addr != null) {
            println("Search match found at "+addr);
            goTo(addr);
        }
        else {
            println("No search matched found.");
        }
    }

}
