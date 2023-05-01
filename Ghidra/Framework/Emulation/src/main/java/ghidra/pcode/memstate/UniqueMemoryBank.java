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
package ghidra.pcode.memstate;

import generic.stl.ComparableMapSTL;
import generic.stl.MapSTL;
import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.AddressSpace;

/**
 * An subclass of {@link MemoryBank} intended for modeling the "unique" memory
 * space.  The space is byte-addressable and paging is not supported.  
 */
public class UniqueMemoryBank extends MemoryBank {

	/**A map from {@link Long} offsets to byte values would require many lookups.
	 * As an optimization, this map is defined from {@link Long} values to 
	 * {@link WordInfo} objects, each of which represents an eight-byte word
	 * of memory.  Each key in this map must be 0 mod 8.
	 */
	protected MapSTL<Long, WordInfo> map = new ComparableMapSTL<Long, WordInfo>();

	private static final long ALIGNMENT_MASK = 0xfffffffffffffff8L;

	//note that WordInfo use the bits in a byte to record whether
	//or not a given byte has been written to, so you can't just 
	//change WORD_SIZE to another value and without also changing
	//the implementation of WordInfo
	private static final int WORD_SIZE = 8;

	private byte[] buffer = new byte[WORD_SIZE];

	public UniqueMemoryBank(AddressSpace spc, boolean isBigEndian) {
		super(spc, isBigEndian, 0, null);
	}

	@Override
	protected MemoryPage getPage(long addr) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	protected void setPage(long addr, byte[] val, int skip, int size, int bufOffset) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	protected void setPageInitialized(long addr, boolean initialized, int skip, int size,
			int bufOffset) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	public int getChunk(long offset, int size, byte[] dest, boolean stopOnUninitialized) {
		int bytesRead = 0;
		if (size == 0) {
			return bytesRead;
		}
		try {
			//align if necessary
			int adjustment = (int) offset % WORD_SIZE;
			if (adjustment != 0) {
				WordInfo word = map.get(offset & ALIGNMENT_MASK);
				if (word == null) {
					throw new LowlevelError("Attempted to read uninitialized word in unique space");
				}
				for (int i = adjustment; i < WORD_SIZE && bytesRead < size; ++i) {
					dest[bytesRead++] = word.getByte(i);
					offset += 1;
				}
			}
			//copy a word at a time
			while (size - bytesRead > 0) {
				WordInfo word = map.get(offset & ALIGNMENT_MASK);
				if (word == null) {
					throw new LowlevelError("Attempted to read uninitialized word in unique space");
				}
				offset += WORD_SIZE;
				//whole word is initialized, copy it (or the appropriate
				//initial segment) all at once
				int bytesToRead = Math.min(WORD_SIZE, size - bytesRead);
				if (word.isEntireWordInitialized()) {
					word.getWord(buffer);
					System.arraycopy(buffer, 0, dest, bytesRead,
						Math.min(WORD_SIZE, size - bytesRead));
					bytesRead += bytesToRead;
					continue;
				}
				//not entirely initialized, copy one byte at a time until 
				//all requested bytes read (or word.getByte throws an exception)
				int base = bytesRead;
				for (int i = 0; i < bytesToRead; ++i) {
					dest[base + i] = word.getByte(i);
					bytesRead += 1;
				}
			}
			return bytesRead;
		}
		catch (LowlevelError e) {
			if (stopOnUninitialized) {
				return bytesRead;
			}
			throw e;
		}
	}

	@Override
	public void setChunk(long offset, int size, byte[] src) {
		if (size == 0 || src.length == 0) {
			return;
		}
		int currentPosition = 0;
		//align if necessary
		int adjustment = (int) offset % WORD_SIZE;
		if (adjustment != 0) {
			WordInfo word = map.get(offset & ALIGNMENT_MASK);
			if (word == null) {
				word = new WordInfo();
				map.put(offset & ALIGNMENT_MASK, word);
			}
			for (int i = adjustment; i < WORD_SIZE; ++i) {
				word.setByte(src[currentPosition], i);
				offset += 1;
				currentPosition += 1;
			}
		}
		while (size > currentPosition) {
			WordInfo word = map.get(offset & ALIGNMENT_MASK);
			if (word == null) {
				word = new WordInfo();
				map.put(offset & ALIGNMENT_MASK, word);
			}
			int bytesToWrite = Math.min(WORD_SIZE, size - currentPosition);
			for (int i = 0; i < bytesToWrite; i++) {
				word.setByte(src[currentPosition + i], i);
			}
			offset += bytesToWrite;
			currentPosition += bytesToWrite;
		}
		return;
	}

	/**
	 * Clear unique storage at the start of an instruction
	 */
	public void clear() {
		map.clear();
	}

	/**
	 * A simple class representing a byte-addressable word of memory.  Each
	 * byte can be either initialized to a byte value or uninitialized.
	 * It is an error to attempt to read an uninitialized byte.
	 */
	public static class WordInfo {
		public byte initialized;
		public long word;

		/**
		 * Constructs a {@link WordInfo} object with all bytes uninitialized.
		 */
		public WordInfo() {
			initialized = 0;
			word = 0;
		}

		/**
		 * Initializes the byte at {@code index} and sets its value to 
		 * {@code val}
		 * @param val new value 
		 * @param index index
		 * @throws LowlevelError if the index is invalid
		 */
		public void setByte(byte val, int index) {
			validateIndex(index);
			word &= ~(0xffL << (WORD_SIZE * index));
			long shifted = ((long) val) << (WORD_SIZE * index);
			word |= shifted;
			initialized |= (1 << index);
		}

		/**
		 * Returns the byte at the given index
		 * @param index index
		 * @return corresponding byte value
		 * @throws LowlevelError if the index is invalid or the requested byte
		 * is not initialized.
		 */
		public byte getByte(int index) {
			validateIndex(index);
			checkInitialized(index);
			long selected = word & (0xffL << (WORD_SIZE * index));
			long adjusted = selected >> (WORD_SIZE * index);
			return (byte) adjusted;
		}

		/**
		 * Writes an entire word into {@code buffer}
		 * @param buffer buffer to write a single word to.  Must have
		 * length 8.
		 * @throws LowlevelError if the entire word is not initialized
		 */
		public void getWord(byte[] buffer) {
			if (initialized != ((byte) (0xff))) {
				throw new LowlevelError("Attempted to read uninitialized word in unique space");
			}
			if (buffer.length != WORD_SIZE) {
				throw new IllegalArgumentException("Buffer must have length 8");
			}
			for (int i = 0; i < WORD_SIZE; ++i) {
				buffer[i] = (byte) ((word & (0xffL << (WORD_SIZE * i))) >> (WORD_SIZE * i));
			}
		}

		/**
		 * Returns true precisely when the entire word is initialized.
		 * @return true if entire work initialized
		 */
		protected boolean isEntireWordInitialized() {
			return initialized == (byte) 0xff;
		}

		//assumes 0 <= index <= 7
		private void checkInitialized(int index) {
			if ((initialized & (1 << (index))) == 0) {
				throw new LowlevelError(
					"Attempted to read uninitialized memory in the unique space.");
			}
		}

		//ensure that the provided index is valid
		private void validateIndex(int index) {
			if (index < 0 || index > 7) {
				throw new LowlevelError("Invalid index: " + Integer.toString(index));
			}
			return;
		}

	}

}
