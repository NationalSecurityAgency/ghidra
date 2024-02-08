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
package sarif.export.ref;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;

public class ExtExternalReference extends ExtReference {
	
	String name;
	String origImport;
	boolean isClass;
	boolean isFunction;
	
	String libLabel;
	String libAddr;
	String libExtAddr;

	public ExtExternalReference(ExternalReference ref) {
		super(ref);
		ExternalLocation extLoc = ref.getExternalLocation();
		String label = extLoc.getLabel();
		Address addr = extLoc.getAddress();
		Address extAddr = extLoc.getExternalSpaceAddress();
		
		name = extLoc.getParentNameSpace().getName(true);
		origImport = extLoc.getOriginalImportedName();
		isClass = extLoc.getClass() != null;
		isFunction = extLoc.getFunction() != null;
		if (label != null) {
			libLabel = label;
		}
		if (addr != null) {
			libAddr = addr.toString();
		}
		if (extAddr != null) {
			libExtAddr = extAddr.toString();
		}
	}

}
