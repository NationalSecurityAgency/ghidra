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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.NoSuchElementException;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Iterator for Global Reference Offsets section of module stream.
 */
class GlobalReferenceOffsetIterator implements ParsingIterator<Long> {

	private PdbByteReader reader;

	private Long currentGlobalReferenceOffset = null;

	/**
	 * An Iterator of Global Reference Offsets
	 * @param reader PdbByteReader containing only Global Reference Offsets information and in
	 * newly constructed state
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException Upon not enough data left to parse
	 */
	public GlobalReferenceOffsetIterator(PdbByteReader reader)
			throws CancelledException, PdbException {
		this.reader = reader;
		processHeader();
	}

	@Override
	public boolean hasNext() {
		if (currentGlobalReferenceOffset == null) {
			find();
		}
		return (currentGlobalReferenceOffset != null);
	}

	@Override
	public Long next() throws NoSuchElementException {
		if (hasNext()) {
			Long returnGlobalReferenceOffset = currentGlobalReferenceOffset;
			currentGlobalReferenceOffset = null;
			return returnGlobalReferenceOffset;
		}
		throw new NoSuchElementException("next() called with no more elements");
	}

	@Override
	public Long peek() throws NoSuchElementException {
		if (hasNext()) {
			return currentGlobalReferenceOffset;
		}
		throw new NoSuchElementException("peek() called with no more elements");
	}

	private void find() {
		try {
			currentGlobalReferenceOffset = reader.parseUnsignedIntVal();
		}
		catch (PdbException e) {
			Msg.error(this, "Problem seen in find()", e);
			currentGlobalReferenceOffset = null;
		}
	}

	/**
	 * Reads and validates size field; leaves reader pointing at first record.
	 * @throws PdbException Upon not enough data left to parse
	 */
	private void processHeader() throws PdbException {
		int sizeField = reader.parseInt();
		if (sizeField + 4 != reader.getLimit()) {
			throw new PdbException(
				String.format("Error in module global refs size field: %d != %d", sizeField,
					reader.getLimit()));
		}
	}

}
