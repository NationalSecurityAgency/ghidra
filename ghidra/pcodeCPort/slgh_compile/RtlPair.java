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
package ghidra.pcodeCPort.slgh_compile;

import ghidra.pcodeCPort.semantics.ConstructTpl;
import ghidra.pcodeCPort.slghsymbol.SymbolScope;

public class RtlPair {
	public ConstructTpl section;	// A p-code section
	public SymbolScope scope;		// and its associated symbol scope

	public RtlPair() {
		section = null;
		scope = null;
	}

	public RtlPair(ConstructTpl sec, SymbolScope sc) {
		section = sec;
		scope = sc;
	}
}
