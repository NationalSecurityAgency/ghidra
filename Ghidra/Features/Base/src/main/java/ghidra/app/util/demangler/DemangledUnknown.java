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
package ghidra.app.util.demangler;

import ghidra.program.model.symbol.SymbolUtilities;

/**
 * An interface to represent an unknown entity that we are demangling.  We want to
 *  represent it in some sort of demangled form in a plate comment, but we do not
 *  know what to lay down yet, or we haven't yet engineered the item that can be
 *  laid down.  If the entity has a variable name, then we would probably make it a
 *  DemangledVariable instead of a DemangledUnknown.
 */
public class DemangledUnknown extends DemangledObject {

	public DemangledUnknown(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled);
		setName(name);
	}

	@Override
	public String getSignature(boolean format) {
		return originalDemangled;
	}

	@Override
	public String getName() {
		//These items likely do not have names or data types, so return the signature.
		String myName = super.getName();
		if (!myName.isEmpty()) {
			return myName;
		}

		String signature = getSignature(true);
		if (!signature.isEmpty()) {
			return SymbolUtilities.replaceInvalidChars(signature, true);
		}

		return "NO_NAME";
	}
}
