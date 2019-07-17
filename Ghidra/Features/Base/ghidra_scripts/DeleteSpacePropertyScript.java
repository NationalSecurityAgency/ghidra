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
//Removes space property that used to be inserted by a plugin, that no longer exists.
//@category Update

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;

import java.util.ArrayList;

public class DeleteSpacePropertyScript extends GhidraScript {

	@Override
    public void run() throws Exception {
		
		PropertyMapManager propMgr = currentProgram.getUsrPropertyManager();
		IntPropertyMap map = propMgr.getIntPropertyMap(CodeUnit.SPACE_PROPERTY);
		if (map != null) {
			AddressIterator iter = map.getPropertyIterator();
			ArrayList<Address> list = new ArrayList<Address>();
			while(iter.hasNext()) {
				list.add(iter.next());
			}
			String str = list.size() > 1? " addresses." : " address.";
			println("Removed space property from "+ list.size() + str);
			for (int i=0; i<list.size(); i++) {
				Address addr = list.get(i);
				map.remove(addr);
			}
		}
		else {
			println("No space properties were found.");
		}
	}

}
