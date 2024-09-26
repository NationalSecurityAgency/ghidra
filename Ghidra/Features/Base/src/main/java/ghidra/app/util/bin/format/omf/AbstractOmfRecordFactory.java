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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

/**
 * Classes that implement this interface can read various flavors of the OMF format
 */
public abstract class AbstractOmfRecordFactory {

	protected BinaryReader reader;

	/**
	 * Creates a new {@link AbstractOmfRecordFactory}
	 * 
	 * @param reader The {@link BinaryReader} used to read records
	 */
	protected AbstractOmfRecordFactory(BinaryReader reader) {
		this.reader = reader;
	}

	/**
	 * Reads the next {@link OmfRecord} pointed to by the reader
	 * 
	 * @return The next read {@link OmfRecord}
	 * @throws IOException if there was an IO-related error
	 * @throws OmfException if there was a problem with the OMF specification
	 */
	public abstract OmfRecord readNextRecord() throws IOException, OmfException;

	/**
	 * Gets a {@link List} of valid record types that can start a supported OMF binary
	 * 
	 * @return A {@link List} of valid record types that can start a supported OMF binary
	 */
	public abstract List<Integer> getStartRecordTypes();

	/**
	 * Gets a valid record type that can end a supported OMF binary
	 * 
	 * @return A valid record types that can end a supported OMF binary
	 */
	public abstract int getEndRecordType();

	/**
	 * {@return the reader associated with this factory}
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Reset this factory's reader to index 0
	 */
	public void reset() {
		reader.setPointerIndex(0);
	}
}
