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

import java.util.Collection;
import java.util.EnumSet;

import ghidra.program.model.mem.MemoryBlock;

public enum TraceMemoryFlag {
	EXECUTE(MemoryBlock.EXECUTE),
	WRITE(MemoryBlock.WRITE),
	READ(MemoryBlock.READ),
	VOLATILE(MemoryBlock.VOLATILE);

	public static EnumSet<TraceMemoryFlag> fromBits(EnumSet<TraceMemoryFlag> flags, int mask) {
		for (TraceMemoryFlag f : TraceMemoryFlag.values()) {
			if ((mask & f.getBits()) != 0) {
				flags.add(f);
			}
		}
		return flags;
	}

	public static Collection<TraceMemoryFlag> fromBits(int mask) {
		return fromBits(EnumSet.noneOf(TraceMemoryFlag.class), mask);
	}

	public static byte toBits(Collection<TraceMemoryFlag> flags) {
		byte bits = 0;
		for (TraceMemoryFlag f : flags) {
			bits |= f.getBits();
		}
		return bits;
	}

	private final byte bits;

	TraceMemoryFlag(int mask) {
		this.bits = (byte) mask;
	}

	public byte getBits() {
		return bits;
	}
}
