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
package ghidra.trace.model.memory;

import ghidra.program.model.mem.MemoryBlock;

public enum TraceMemoryFlag {
	EXECUTE(MemoryBlock.EXECUTE),
	WRITE(MemoryBlock.WRITE),
	READ(MemoryBlock.READ),
	VOLATILE(MemoryBlock.VOLATILE);

	private final byte bits;

	TraceMemoryFlag(int mask) {
		this.bits = (byte) mask;
	}

	public byte getBits() {
		return bits;
	}
}
