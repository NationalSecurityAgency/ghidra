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
package ghidra.app.plugin.core.strings;

import java.util.Iterator;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.TaskMonitor;

/**
 * Iterator that searches for locations that could be strings and returns 
 * {@link StringDataInstance}s representing those locations.
 */
public class UndefinedStringIterator
		implements Iterator<StringDataInstance>, Iterable<StringDataInstance> {
	private static final int MAX_SANE_STRING_LENGTH = 1024 * 1024; // 1mb

	static AddressSet getSingleStringEndAddrRange(Program program, AddressSetView addrs) {
		Address minAddr = addrs.getMinAddress();
		MemoryBlock memblock = program.getMemory().getBlock(minAddr);
		Address endAddr = memblock != null ? memblock.getEnd() : minAddr;
		if (endAddr.subtract(minAddr) > MAX_SANE_STRING_LENGTH) {
			endAddr = minAddr.add(MAX_SANE_STRING_LENGTH);
		}
		return new AddressSet(minAddr, endAddr);
	}

	private final TaskMonitor monitor;
	private final Listing listing;
	private final Program program;
	private final Memory memory;
	private final AddressSet addrs;
	private final int charSize;
	private final int charAlignment;
	private final boolean breakOnRef;
	private final Address singleStringStart;
	private final AbstractStringDataType stringDataType;
	private final Settings stringSettings;
	private final long origAddrCount;
	private final byte[] buffer = new byte[64];
	private StringDataInstance currentItem;

	/**
	 * Creates a new UndefinedStringIterator instance.
	 * 
	 * @param program {@link Program}
	 * @param addrs set of {@link Address}es to search.
	 * @param charSize size of the characters (and the null-terminator) that make up the string
	 * @param charAlignment alignment requirements for the start of the string 
	 * @param breakOnRef boolean flag, if true strings will be terminated early at locations that
	 * have an in-bound memory reference
	 * @param singleStringMode boolean flag, if true only one string will be returned, and it must
	 * be located at the start of the specified address set (after alignment tweaks)
	 * @param stringDataType a string data type that corresponds to the type of string being
	 * searched for
	 * @param stringSettings {@link Settings} for the string data type
	 * @param monitor {@link TaskMonitor}
	 */
	public UndefinedStringIterator(Program program, AddressSetView addrs, int charSize,
			int charAlignment, boolean breakOnRef, boolean singleStringMode,
			AbstractStringDataType stringDataType, Settings stringSettings, TaskMonitor monitor) {
		this.program = program;
		this.listing = program.getListing();
		this.memory = program.getMemory();
		this.addrs = new AddressSet(addrs);
		this.charSize = charSize;
		this.charAlignment = charAlignment;
		this.breakOnRef = breakOnRef;
		this.singleStringStart = singleStringMode ? addrs.getMinAddress() : null;
		this.stringDataType = stringDataType;
		this.stringSettings = stringSettings;
		this.monitor = monitor;
		this.origAddrCount = addrs.getNumAddresses();
		monitor.initialize(origAddrCount);
	}

	@Override
	public Iterator<StringDataInstance> iterator() {
		return this;
	}

	@Override
	public boolean hasNext() {
		if (currentItem == null) {
			currentItem = findNext();
		}
		return currentItem != null;
	}

	@Override
	public StringDataInstance next() {
		StringDataInstance result = currentItem;
		currentItem = null;
		return result;
	}

	private StringDataInstance findNext() {
		forceAlignment();
		while (!addrs.isEmpty()) {
			if (monitor.isCancelled()) {
				return null;
			}

			if (!findStartOfString()) {
				break;
			}

			monitor.setProgress(origAddrCount - addrs.getNumAddresses());

			Address addr = addrs.getMinAddress();
			Data undefData = listing.getDataAt(addr);
			if (undefData == null) {
				break;
			}
			Address eos = findEndOfString();
			if (monitor.isCancelled()) {
				return null;
			}

			addrs.deleteFromMin(eos);
			long length = eos.subtract(addr) + 1;
			if (length < charSize || length > MAX_SANE_STRING_LENGTH) {
				// throw away, try next string
				continue;
			}

			StringDataInstance sdi =
				stringDataType.getStringDataInstance(undefData, stringSettings, (int) length);
			return sdi;

		}
		return null;
	}

	private void forceAlignment() {
		while (!addrs.isEmpty() && addrs.getMinAddress().getOffset() % charAlignment != 0) {
			addrs.deleteFromMin(addrs.getMinAddress());
		}
	}

	private boolean findStartOfString() {
		return consumeNullTerms() && !addrs.isEmpty();
	}

	private Address findEndOfString() {
		// search for an end-of-string location
		// 1) null terminator
		// 2) inbound ref
		// 3) end-of-memory-block
		Address max = addrs.getFirstRange().getMaxAddress();
		Address bufStart = addrs.getFirstRange().getMinAddress();
		try {
			do {
				Address refdAddr = breakOnRef ? getNextRefdAddr(bufStart, max) : null;
				if (refdAddr != null) {
					max = refdAddr;
				}

				int bytesToRead = (int) Math.min(buffer.length, max.subtract(bufStart) + 1);
				int bytesRead = memory.getBytes(bufStart, buffer, 0, bytesToRead);
				if (bytesRead <= 0) {
					break;
				}
				for (int nullIndex = 0; nullIndex <= bytesRead - charSize; nullIndex += charSize) {
					if (isNullChar(nullIndex)) {
						// found a null term char, return it (inclusive)
						return bufStart.addNoWrap(nullIndex + charSize - 1);
					}
				}

				if (refdAddr != null) {
					// always terminate if there was a inbound ref
					return refdAddr.previous();
				}

				// loop and read next chunk and try again
				bufStart = bufStart.addNoWrap(bytesRead);
			}
			while (bufStart.compareTo(max) <= 0);
		}
		catch (MemoryAccessException | AddressOverflowException e) {
			// terminate loop/method
		}
		return max;
	}

	private boolean isNullChar(int index) {
		for (int i = 0; i < charSize; i++) {
			if (buffer[index + i] != 0) {
				return false;
			}
		}
		return true;
	}

	private Address getNextRefdAddr(Address start, Address end) {
		AddressIterator it = program.getReferenceManager()
				.getReferenceDestinationIterator(new AddressSet(start, end), true);
		Address refdAddr = null;
		if (it.hasNext()) {
			refdAddr = it.next();
			if (start.equals(refdAddr)) {
				refdAddr = it.hasNext() ? it.next() : null;
			}
		}
		return refdAddr;
	}

	private boolean consumeNullTerms() {
		try {
			if (memory.getByte(addrs.getMinAddress()) == 0) {
				int bytesRead;
				while (!addrs.isEmpty() && !monitor.isCancelled() &&
					(bytesRead = memory.getBytes(addrs.getMinAddress(), buffer, 0,
						(int) Math.min(buffer.length, addrs.getFirstRange().getLength()))) > 0) {

					int nonNullIndex;
					for (nonNullIndex = 0; nonNullIndex < bytesRead; nonNullIndex++) {
						if (buffer[nonNullIndex] != 0) {
							nonNullIndex -= nonNullIndex % charSize;
							break;
						}
					}
					if (nonNullIndex > 0) {
						addrs.deleteFromMin(addrs.getMinAddress().add(nonNullIndex - 1));
					}
					if (nonNullIndex < bytesRead) {
						break;
					}
				}
			}
		}
		catch (MemoryAccessException e) {
			// terminate loop/method
		}
		if (singleStringStart != null &&
			Math.abs(singleStringStart.subtract(addrs.getMinAddress())) >= charAlignment) {
			return false;
		}
		return true;
	}
}
