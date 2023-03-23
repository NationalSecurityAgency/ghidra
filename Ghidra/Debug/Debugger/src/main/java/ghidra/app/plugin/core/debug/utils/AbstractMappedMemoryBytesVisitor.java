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
package ghidra.app.plugin.core.debug.utils;

import java.util.Collection;
import java.util.Map.Entry;
import java.util.Objects;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.trace.model.Trace;
import ghidra.util.MathUtilities;

/**
 * An object for visiting the memory of mapped programs on a block-by-block basis
 *
 * <p>
 * The task for reading portions of program memory from the perspective of a trace, via the static
 * mapping service turns out to be fairly onerous. This class attempts to ease that logic. In its
 * simplest use, the client need only implement {@link #visitData(Address, byte[], int)} and provide
 * a reference to the mapping service. Then, calling {@link #visit(Trace, long, AddressSetView)}
 * will result in several calls to {@link #visitData(Address, byte[], int)}, which will provide the
 * bytes from the mapped programs, along with the trace address where they apply.
 */
public abstract class AbstractMappedMemoryBytesVisitor {
	private final DebuggerStaticMappingService mappingService;
	private final byte[] buffer;

	/**
	 * Construct a visitor object
	 * 
	 * @param mappingService the mapping service
	 * @param buffer a buffer for the data. This is passed directly into
	 *            {@link #visitData(Address, byte[], int)}. If a mapped range exceeds the buffer
	 *            size, the range is broken down into smaller pieces.
	 */
	public AbstractMappedMemoryBytesVisitor(DebuggerStaticMappingService mappingService,
			byte[] buffer) {
		this.mappingService = Objects.requireNonNull(mappingService);
		this.buffer = buffer;
	}

	/**
	 * Choose what portions of a mapped program to include
	 * 
	 * <p>
	 * By default, this is the set of loaded and initialized memory addresses
	 * 
	 * @param memory the mapped program's memory
	 * @return the address set to include
	 */
	protected AddressSetView includeFromProgram(Memory memory) {
		return memory.getLoadedAndInitializedAddressSet();
	}

	/**
	 * Read bytes from a mapped program into a buffer
	 * 
	 * <p>
	 * By default, this is a straightforward call to
	 * {@link Memory#getBytes(Address, byte[], int, int)}.
	 * 
	 * @param memory the mapped program's memory
	 * @param addr the starting address
	 * @param dest the destination buffer
	 * @param size the number of bytes to read
	 * @return the number of bytes actually read
	 * @throws MemoryAccessException if the read fails
	 */
	protected int read(Memory memory, Address addr, byte[] dest, int size)
			throws MemoryAccessException {
		return memory.getBytes(addr, dest, 0, size);
	}

	/**
	 * Visit a trace's mapped programs
	 * 
	 * @param trace the trace
	 * @param snap the snapshot for the mappings
	 * @param hostView the address set (per the trace's "host" platform)
	 * @return true if any range was visited
	 * @throws MemoryAccessException upon the first read failure
	 */
	public boolean visit(Trace trace, long snap, AddressSetView hostView)
			throws MemoryAccessException {
		boolean result = false;
		for (Entry<Program, Collection<MappedAddressRange>> ent : mappingService
				.getOpenMappedViews(trace, hostView, snap)
				.entrySet()) {
			result |= visitProgram(ent.getKey(), ent.getValue());
		}
		return result;
	}

	/**
	 * Visit a mapped program
	 * 
	 * @param program the mapped program
	 * @param mappedSet the portion of memory that was mapped from the trace
	 * @return true if any range was visited
	 * @throws MemoryAccessException upon the first read failure
	 */
	protected boolean visitProgram(Program program, Collection<MappedAddressRange> mappedSet)
			throws MemoryAccessException {
		boolean result = false;
		Memory memory = program.getMemory();
		AddressSetView included = includeFromProgram(memory);
		for (MappedAddressRange mappedRng : mappedSet) {
			AddressRange progRng = mappedRng.getDestinationAddressRange();
			for (AddressRange subProgRng : included.intersectRange(progRng.getMinAddress(),
				progRng.getMaxAddress())) {
				result |= visitRange(program, subProgRng, mappedRng);
			}
		}
		return result;
	}

	/**
	 * Visit a mapped range
	 * 
	 * @param program the program
	 * @param progRng the range in the program
	 * @param mappedRng the mapped range from the trace
	 * @return true if the range was visited
	 * @throws MemoryAccessException upon the first read failure
	 */
	protected boolean visitRange(Program program, AddressRange progRng,
			MappedAddressRange mappedRng) throws MemoryAccessException {
		Memory memory = program.getMemory();
		AddressSpace progSpace = progRng.getAddressSpace();
		long lower = progRng.getMinAddress().getOffset();
		long fullLen = progRng.getLength();
		while (fullLen > 0) {
			int len = MathUtilities.unsignedMin(buffer.length, fullLen);
			Address progAddr = progSpace.getAddress(lower);
			int read = read(memory, progAddr, buffer, len);
			Address hostAddr = mappedRng.mapDestinationToSource(progAddr);
			visitData(hostAddr, buffer, read);
			lower += len;
			fullLen -= len;
		}
		return true;
	}

	/**
	 * Visit a block of data
	 * 
	 * <p>
	 * <b>NOTE:</b> Not to be confused with {@link MemoryBlock}. This delivers the final results of
	 * the visit. It is called once per block of data read from a mapped program.
	 * 
	 * @param hostAddr the trace address (per the trace's "host" platform)
	 * @param data the buffer of bytes read from the program
	 * @param size the number of valid bytes in the buffer. Valid bytes, if any, start at index 0
	 */
	protected abstract void visitData(Address hostAddr, byte[] data, int size);
}
