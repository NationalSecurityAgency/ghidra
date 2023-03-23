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
package ghidra.app.emulator.memory;

import java.util.Arrays;

import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryPage;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

// Derived from ProgramMappedMemory
public class ProgramLoadImage {

	private Program program;
	private AddressSetView initializedAddressSet;
	private MemoryFaultHandler faultHandler;

	public ProgramLoadImage(Program program, MemoryFaultHandler faultHandler) {
		this.program = program;
		Memory memory = program.getMemory();
		initializedAddressSet = memory.getLoadedAndInitializedAddressSet();
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() && block.isMapped()) {
				initializedAddressSet = addMappedInitializedMemory(block);
			}
		}
		this.faultHandler = faultHandler;
		// TODO: consider adding program consumer (would require proper dispose)
	}

	private AddressSetView addMappedInitializedMemory(MemoryBlock mappedBlock) {
		MemoryBlockSourceInfo sourceInfo = mappedBlock.getSourceInfos().get(0); // mapped block has exactly 1 mapped source
		if (!sourceInfo.getMappedRange().isPresent()) {
			throw new AssertException("Mapped block did not have mapped range!");
		}
		AddressRange mappedRange = sourceInfo.getMappedRange().get();
		Address mapStart = mappedRange.getMinAddress();
		Address mapEnd = mappedRange.getMaxAddress();
		AddressSet modifiedSet = new AddressSet(initializedAddressSet);
		AddressSet mappedAreas = initializedAddressSet.intersectRange(mapStart, mapEnd);
		for (AddressRange range : mappedAreas) {
			Address start = mappedBlock.getStart().add(range.getMinAddress().subtract(mapStart));
			Address end = mappedBlock.getStart().add(range.getMaxAddress().subtract(mapStart));
			modifiedSet.add(start, end);
		}
		return modifiedSet;
	}

	public void dispose() {
		// do nothing
	}

	// TODO: Need to investigate program write-back transaction issues -
	// it could also be very expensive writing memory without some form of write-back cache
	public void write(byte[] bytes, int size, Address addr, int offset) {
		Memory memory = program.getMemory();
		int currentOffset = offset;
		int remaining = size;
		Address nextAddr = addr;
		Address endAddr;
		try {
			endAddr = addr.addNoWrap(size - 1);
		}
		catch (AddressOverflowException e) {
			throw new LowlevelError(
				"Illegal memory write request: " + addr + ", length=" + size + " bytes");
		}
		while (true) {
			int chunkSize = remaining;
			AddressRangeIterator it = initializedAddressSet.getAddressRanges(nextAddr, true);
			AddressRange range = it.hasNext() ? it.next() : null;

			///
			/// Begin change for addressSet changes - wcb		
			///

			if (range == null) {
				// nextAddr not in memory and is bigger that any initialized memory
				handleWriteFault(bytes, currentOffset, remaining, nextAddr);
				break;
			}
			else if (range.contains(nextAddr)) {
				// nextAddr is in memory
				if (endAddr.compareTo(range.getMaxAddress()) > 0) {
					chunkSize = (int) (range.getMaxAddress().subtract(nextAddr) + 1);
				}
				try {
					memory.setBytes(nextAddr, bytes, currentOffset, chunkSize);
				}
				catch (MemoryAccessException e) {
					throw new LowlevelError("Unexpected memory write error: " + e.getMessage());
				}
			}
			else {
				// nextAddr not in initialized memory, but is less than some initialized range
				Address rangeAddr = range.getMinAddress();
				if (!rangeAddr.getAddressSpace().equals(addr.getAddressSpace())) {
					handleWriteFault(bytes, currentOffset, remaining, nextAddr);
					break;
				}
				long gapSize = rangeAddr.subtract(nextAddr);
				chunkSize = (int) Math.min(gapSize, remaining);
				handleWriteFault(bytes, currentOffset, chunkSize, nextAddr);
			}

			///
			/// End change for addressSet changes - wcb		
			///

			if (chunkSize == remaining) {
				break; // done
			}

			// prepare for next chunk
			try {
				nextAddr = nextAddr.addNoWrap(chunkSize);
			}
			catch (AddressOverflowException e) {
				throw new LowlevelError("Unexpected error: " + e.getMessage());
			}
			currentOffset += chunkSize;
			remaining -= chunkSize;
		}

	}

	private void handleWriteFault(byte[] bytes, int currentOffset, int remaining,
			Address nextAddr) {
		// TODO: Should we create blocks or convert to initialized as needed ?
	}

	public byte[] read(byte[] bytes, int size, Address addr, int offset,
			boolean generateInitializedMask) {

		Memory memory = program.getMemory();
		int currentOffset = offset;
		int remaining = size;
		Address nextAddr = addr;
		Address endAddr;
		byte[] initializedMask = null;
		try {
			endAddr = addr.addNoWrap(size - 1);
		}
		catch (AddressOverflowException e) {
			throw new LowlevelError(
				"Illegal memory read request: " + addr + ", length=" + size + " bytes");
		}
		while (true) {
			int chunkSize = remaining;

			///
			/// Begin change for addressSet changes - wcb		
			///

			AddressRangeIterator it = initializedAddressSet.getAddressRanges(nextAddr, true);
			AddressRange range = it.hasNext() ? it.next() : null;

			if (range == null) {
				if (generateInitializedMask) {
					initializedMask = getInitializedMask(bytes.length, offset, currentOffset,
						remaining, initializedMask);
				}
				else {
					handleReadFault(bytes, currentOffset, remaining, nextAddr);
				}
				break;
			}
			else if (range.contains(nextAddr)) {
				// nextAddr found in initialized memory
				if (endAddr.compareTo(range.getMaxAddress()) > 0) {
					chunkSize = (int) (range.getMaxAddress().subtract(nextAddr) + 1);
				}
				try {
					memory.getBytes(nextAddr, bytes, currentOffset, chunkSize);
				}
				catch (MemoryAccessException e) {
					//throw new LowlevelError("Unexpected memory read error: " + e.getMessage());
					Msg.warn(this, "Unexpected memory read error: " + e.getMessage());
				}
			}
			else {
				Address rangeAddr = range.getMinAddress();
				if (!rangeAddr.getAddressSpace().equals(addr.getAddressSpace())) {
					if (generateInitializedMask) {
						initializedMask = getInitializedMask(bytes.length, offset, currentOffset,
							remaining, initializedMask);
					}
					else {
						handleReadFault(bytes, currentOffset, remaining, nextAddr);
					}
					break;
				}

				long gapSize = rangeAddr.subtract(nextAddr);
				chunkSize = (gapSize > 0) ? (int) Math.min(gapSize, remaining) : remaining;
				if (generateInitializedMask) {
					initializedMask = getInitializedMask(bytes.length, offset, currentOffset,
						chunkSize, initializedMask);
				}
				else {
					handleReadFault(bytes, currentOffset, chunkSize, nextAddr);
				}
			}
			///
			/// End change for addressSet changes - wcb		
			///

			if (chunkSize == remaining) {
				break; // done
			}

			// prepare for next chunk
			try {
				nextAddr = nextAddr.addNoWrap(chunkSize);
			}
			catch (AddressOverflowException e) {
				throw new LowlevelError("Unexpected error: " + e.getMessage());
			}
			currentOffset += chunkSize;
			remaining -= chunkSize;
		}
		return initializedMask;
	}

	private static byte[] getInitializedMask(int bufsize, int initialOffset,
			int uninitializedOffset, int uninitializedSize, byte[] initializedMask) {
		if (initializedMask == null) {
			initializedMask = MemoryPage.getInitializedMask(bufsize, 0, initialOffset, false);
		}
		MemoryPage.setUninitialized(initializedMask, uninitializedOffset, uninitializedSize);
		return initializedMask;
	}

	private void handleReadFault(byte[] bytes, int offset, int size, Address addr) {
// NOTE: This can trigger a load from a different external library depending upon the specific fault handler installed
		Arrays.fill(bytes, offset, offset + size, (byte) 0);
		if (faultHandler != null) {
			faultHandler.uninitializedRead(addr, size, bytes, size);
		}
	}

	public AddressSetView getInitializedAddressSet() {
		return initializedAddressSet;
	}

}
