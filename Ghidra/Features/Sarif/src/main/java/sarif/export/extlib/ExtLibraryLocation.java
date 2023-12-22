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
package sarif.export.extlib;

import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.symbol.ExternalLocation;

public class ExtLibraryLocation implements IsfObject {

	String name;
	String location;
	String originalImportedName;
	String externalAddress;
	String symbol;
	boolean isFunction = false;
	boolean isClass = false;
	String source;

	public ExtLibraryLocation(ExternalLocation extLoc) {
		name = extLoc.getLabel();
		originalImportedName = extLoc.getOriginalImportedName();
		location = extLoc.getParentNameSpace().getName(true);
		externalAddress = extLoc.getExternalSpaceAddress().toString();
		isFunction = extLoc.getFunction() != null;
		isClass = extLoc.getClass() != null;
		source = extLoc.getSource().toString();
		symbol = extLoc.getSymbol().getName();
	}

//	public ExtLibraryLocation(GhidraClass cls, ExternalLocation extLoc) {
//		name = extLoc.getLabel();
//		originalImportedName = extLoc.getOriginalImportedName();
//		location = extLoc.getParentName();
//		//location = cls.getParentNamespace().getName();
//		externalAddress = extLoc.getExternalSpaceAddress().toString();
//		Function f = extLoc.getFunction();
//		isFunction = f != null;
//		source = extLoc.getSource().toString();
//		symbol = extLoc.getSymbol().getName(true);
//	}
}
