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
package ghidra.app.util.pdb.classtype;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.Pointer;

public class VirtualFunctionTableEntry implements VFTableEntry {
	SymbolPath originalMethodPath;
	SymbolPath overrideMethodPath;
	Pointer functionPointer;

	public VirtualFunctionTableEntry(SymbolPath originalMethodPath, SymbolPath overrideMethodPath,
			Pointer functionPointer) {
		this.originalMethodPath = originalMethodPath;
		this.overrideMethodPath = overrideMethodPath;
		this.functionPointer = functionPointer;
	}

	@Override
	public void setOriginalPath(SymbolPath path) {
		originalMethodPath = path;
	}

	@Override
	public SymbolPath getOriginalPath() {
		return originalMethodPath;
	}

	@Override
	public void setOverridePath(SymbolPath path) {
		overrideMethodPath = path;
	}

	@Override
	public SymbolPath getOverridePath() {
		return overrideMethodPath;
	}

	@Override
	public void setFunctionPointer(Pointer pointer) {
		functionPointer = pointer;
	}

	@Override
	public Pointer getFunctionPointer() {
		return functionPointer;
	}

}
