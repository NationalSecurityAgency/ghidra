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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import ghidra.util.task.TaskMonitor;

/**
 * Class for C13Type COFF_SYMBOL_RVA.
 * <p>
 * This temporary class implementation currently extends {@link AbstractUnimplementedC13Section},
 * but this should be changed to {@link C13Section} when the format is understood and the
 * implementation is made concrete.
 */
class C13CoffSymbolRva extends AbstractUnimplementedC13Section {
	static C13CoffSymbolRva parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor) {
		return new C13CoffSymbolRva(reader, ignore, monitor);
	}

	protected C13CoffSymbolRva(PdbByteReader reader, boolean ignore, TaskMonitor monitor) {
		super(reader, ignore, monitor);
	}
}
