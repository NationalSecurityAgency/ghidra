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
package ghidra.program.util.string;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.string.StringTableOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.ascii.*;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractStringSearcher {
	private Program program;
	private List<ByteStreamCharMatcher> matchers;
	private int alignment;

	protected AbstractStringSearcher(Program program, CharSetRecognizer charSet,
			int minimumStringSize, int alignment, boolean includeUTF8, boolean includeUTF16,
			boolean includeUTF32) {

		this.program = program;
		this.alignment = alignment;
		Endian endian = program.getLanguage().isBigEndian() ? Endian.BIG : Endian.LITTLE;

		matchers = new ArrayList<>();

		if (includeUTF8) {
			matchers.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF8,
				endian, alignment, 0));
		}
		if (includeUTF16) {
			addUTF16Matchers(matchers, charSet, endian, minimumStringSize);
		}
		if (includeUTF32) {
			addUTF32Matchers(matchers, charSet, endian, minimumStringSize);
		}

	}

	private void addUTF16Matchers(List<ByteStreamCharMatcher> matchersList,
			CharSetRecognizer charSet, Endian endian, int minimumStringSize) {

		matchersList.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF16,
			endian, getAlignment(), 0));

		if (getAlignment() == 1) {
			matchersList.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF16,
				endian, getAlignment(), 1));
		}

	}

	private void addUTF32Matchers(List<ByteStreamCharMatcher> matchersList,
			CharSetRecognizer charSet, Endian endian, int minimumStringSize) {

		matchers.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF32, endian,
			getAlignment(), 0));

		if (getAlignment() == 2 || getAlignment() == 1) {
			matchers.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF32,
				endian, getAlignment(), 2));
		}

		if (getAlignment() == 1) {
			matchers.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF32,
				endian, getAlignment(), 1));
			matchers.add(new MultiByteCharMatcher(minimumStringSize, charSet, CharWidth.UTF32,
				endian, getAlignment(), 3));
		}
	}

	/**
	 * Searches the given addressSet for strings. 
	 * <p>
	 * Note: The address set searched will be modified before searching in the following ways:
	 * <ul>
	 * <li> if the given set is null, it will be re-initialized to encompass all of program memory</li>
	 * <li> the set will be further culled to only include loaded memory blocks, if specified</li>
	 * </ul>
	 * <p>
	 * @param addressSet the address set to search over; if null, will initialized to all memory
	 * @param callback the callback invoked when a string is found
	 * @param searchLoadedMemoryBlocksOnly if true, will exclude unloaded memory blocks from the search
	 * @param monitor the user monitor
	 * @return the updated address set used for the search
	 */
	public AddressSetView search(AddressSetView addressSet, FoundStringCallback callback,
			boolean searchLoadedMemoryBlocksOnly, TaskMonitor monitor) {

		addressSet = addressSet == null ? program.getMemory() : addressSet;

		AddressSetView updatedAddressSet =
			updateAddressesToSearch(addressSet, searchLoadedMemoryBlocksOnly);

		AddressRangeIterator addressRanges = updatedAddressSet.getAddressRanges();

		monitor.initialize(addressSet.getNumAddresses());
		while (addressRanges.hasNext()) {
			if (monitor.isCancelled()) {
				return updatedAddressSet;
			}

			AddressRange range = addressRanges.next();
			searchRange(range, callback, monitor);
		}

		return updatedAddressSet;
	}

	/**
	 * Returns a new address set that is the intersection of the given set with the
	 * desired memory block addresses (loaded or unloaded).
	 * <p>
	 * Note: This desired set of memory blocks is known by inspecting the 
	 * {@link StringTableOptions#useLoadedBlocksOnly()} attribute set by the user. 
	 * 
	 * @param addressSet the address set to update
	 * @param useLoadedBlocksOnly if true, only return addresses in loaded memory blocks
	 * @return new the new address set
	 */
	public AddressSetView updateAddressesToSearch(AddressSetView addressSet,
			boolean useLoadedBlocksOnly) {
		AddressSetView updatedAddressSet;

		if (useLoadedBlocksOnly) {
			updatedAddressSet =
				addressSet.intersect(program.getMemory().getLoadedAndInitializedAddressSet());
		}
		else {
			updatedAddressSet =
				addressSet.intersect(program.getMemory().getAllInitializedAddressSet());
		}

		return updatedAddressSet;
	}

	private void searchRange(AddressRange range, FoundStringCallback callback,
			TaskMonitor monitor) {
		matchers.forEach(m -> m.reset());
		range = adjustRangeForAlignment(range);
		MemBuffer buf = new MemoryBufferImpl(program.getMemory(), range.getMinAddress());
		long length = range.getLength();
		for (int i = 0; i < length; i++) {
			if (monitor.isCancelled()) {
				return;
			}

			if (i % 1000 == 999) {
				monitor.incrementProgress(1000);
			}
			byte b = getByte(buf, i);
			for (ByteStreamCharMatcher matcher : matchers) {
				if (matcher.add(b)) {
					processSequence(callback, matcher.getSequence(), buf);
				}
			}
		}

		for (ByteStreamCharMatcher matcher : matchers) {
			if (matcher.endSequence()) {
				processSequence(callback, matcher.getSequence(), buf);
			}
		}

	}

	private AddressRange adjustRangeForAlignment(AddressRange range) {
		if (getAlignment() == 1) {
			return range;
		}
		long offset = range.getMinAddress().getOffset();
		long mod = offset % getAlignment();
		if (mod == 0) {
			return range;
		}
		Address newStart = range.getMinAddress().getNewAddress(offset + getAlignment() - mod);
		return new AddressRangeImpl(newStart, range.getMaxAddress());
	}

	private byte getByte(MemBuffer buf, int i) {
		try {
			return buf.getByte(i);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	protected abstract void processSequence(FoundStringCallback callback, Sequence sequence,
			MemBuffer buf);

	protected FoundString getFoundString(MemBuffer buf, Sequence sequence,
			DataType stringDataType) {
		Address address = buf.getAddress().add(sequence.getStart());
		return new FoundString(address, sequence.getLength(), stringDataType);

	}

	public int getAlignment() {
		return alignment;
	}

}
