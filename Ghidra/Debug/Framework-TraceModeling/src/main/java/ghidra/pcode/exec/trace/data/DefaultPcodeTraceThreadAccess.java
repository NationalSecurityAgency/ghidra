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
package ghidra.pcode.exec.trace.data;

import java.nio.ByteBuffer;

import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * The default data-access shim, for both memory and registers
 *
 * <p>
 * This is not designed for use with the emulator, but rather with stand-alone p-code executors,
 * e.g., to evaluate a Sleigh expression. It multiplexes a given memory access shim and another
 * register access shim into a single shim for use in one state piece.
 */
public class DefaultPcodeTraceThreadAccess
		implements PcodeTraceMemoryAccess, PcodeTraceRegistersAccess {

	protected final PcodeTraceMemoryAccess memory;
	protected final PcodeTraceRegistersAccess registers;

	/**
	 * Construct a shim
	 * 
	 * @param memory the memory access shim
	 * @param registers the regsiter access shim
	 */
	protected DefaultPcodeTraceThreadAccess(PcodeTraceMemoryAccess memory,
			PcodeTraceRegistersAccess registers) {
		this.memory = memory;
		this.registers = registers;
	}

	@Override
	public Language getLanguage() {
		return memory.getLanguage();
	}

	@Override
	public void setState(AddressRange range, TraceMemoryState state) {
		if (range.getAddressSpace().isRegisterSpace()) {
			registers.setState(range, state);
			return;
		}
		memory.setState(range, state);
	}

	@Override
	public TraceMemoryState getViewportState(AddressRange range) {
		if (range.getAddressSpace().isRegisterSpace()) {
			return registers.getViewportState(range);
		}
		return memory.getViewportState(range);
	}

	@Override
	public AddressSetView intersectViewKnown(AddressSetView view, boolean useFullSpans) {
		return memory.intersectViewKnown(view, useFullSpans)
				.union(registers.intersectViewKnown(view, useFullSpans));
	}

	@Override
	public AddressSetView intersectUnknown(AddressSetView view) {
		return memory.intersectUnknown(view).union(registers.intersectUnknown(view));
	}

	@Override
	public int putBytes(Address start, ByteBuffer buf) {
		if (start.isRegisterAddress()) {
			return registers.putBytes(start, buf);
		}
		return memory.putBytes(start, buf);
	}

	@Override
	public int getBytes(Address start, ByteBuffer buf) {
		if (start.isRegisterAddress()) {
			return registers.getBytes(start, buf);
		}
		return memory.getBytes(start, buf);
	}

	@Override
	public Address translate(Address address) {
		if (address.isRegisterAddress()) {
			return registers.translate(address);
		}
		return memory.translate(address);
	}

	@Override
	public <T> PcodeTracePropertyAccess<T> getPropertyAccess(String name, Class<T> type) {
		throw new UnsupportedOperationException("This is meant for p-code executor use");
	}

	@Override
	public void initializeThreadContext(PcodeThread<?> thread) {
		registers.initializeThreadContext(thread);
	}
}
