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
package ghidra.app.util.bin.format.macho.commands.dyld;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class used to represent the generic components of a Mach-O opcode table
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOLayout.cpp">common/MachOLayout.cpp</a> 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOAnalyzer.cpp">common/MachOAnalyzer.cpp</a> 
 */
public abstract class OpcodeTable {

	protected List<Long> opcodeOffsets = new ArrayList<>();
	protected List<Long> ulebOffsets = new ArrayList<>();
	protected List<Long> slebOffsets = new ArrayList<>();
	protected List<Long> stringOffsets = new ArrayList<>();

	/**
	 * {@return opcode offsets from the start of the bind data}
	 */
	public List<Long> getOpcodeOffsets() {
		return opcodeOffsets;
	}

	/**
	 * {@return ULEB128 offsets from the start of the bind data}
	 */
	public List<Long> getUlebOffsets() {
		return ulebOffsets;
	}

	/**
	 * {@return SLEB128 offsets from the start of the bind data}
	 */
	public List<Long> getSlebOffsets() {
		return slebOffsets;
	}

	/**
	 * {@return string offsets from the start of the bind data}
	 */
	public List<Long> getStringOffsets() {
		return stringOffsets;
	}
}
