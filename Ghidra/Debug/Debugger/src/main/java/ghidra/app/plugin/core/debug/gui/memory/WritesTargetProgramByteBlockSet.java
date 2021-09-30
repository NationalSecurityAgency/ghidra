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
package ghidra.app.plugin.core.debug.gui.memory;

import ghidra.app.plugin.core.byteviewer.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class WritesTargetProgramByteBlockSet extends ProgramByteBlockSet {
	protected final DebuggerMemoryBytesProvider provider;

	public WritesTargetProgramByteBlockSet(DebuggerMemoryBytesProvider provider,
			Program program, ByteBlockChangeManager bbcm) {
		super(provider, program, bbcm);
		this.provider = provider;
	}

	@Override
	protected MemoryByteBlock newMemoryByteBlock(Memory memory, MemoryBlock memBlock) {
		return new WritesTargetMemoryByteBlock(this, program, memory, memBlock);
	}
}
