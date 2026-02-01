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
package ghidra.sleigh.grammar;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

/**
 * This class is used to index source files in a SLEIGH language module.
 * The SLEIGH compiler records the index of the source file for a constructor rather
 * than the file name.  This is an optimization to avoid repeating the file name in
 * the .sla files.  
 */
public class SourceFileIndexer {

	private BiMap<String, Integer> filenameToIndex;
	private int leastUnusedIndex;

	/**
	 * Creates a {code SourceFileIndexer} object with an empty index.
	 */
	public SourceFileIndexer() {
		filenameToIndex = HashBiMap.create();
		leastUnusedIndex = 0;
	}

	/**
	 * Adds the filename of a location to the index if it is not already present.
	 * @param loc location containing filename to add
	 * @return index associated with filename, or {@code null} if a {@code null} {@link Location}
	 * or a {@link Location} with a {@code null} filename was provided as input.
	 */
	public Integer index(Location loc) {
		if (loc == null) {
			Msg.info(this, "null Location");
			return null;
		}
		String filename = loc.filename;
		if (filename == null) {
			Msg.info(this, "null filename");
			return null;
		}
		Integer res = filenameToIndex.putIfAbsent(filename, leastUnusedIndex);
		if (res == null) {
			return leastUnusedIndex++;
		}
		return res;
	}

	/**
	 * Returns the index for a filename
	 * @param filename file
	 * @return index or {@code null} if {@code filename} is not in the index.
	 */
	public Integer getIndex(String filename) {
		return filenameToIndex.get(filename);
	}

	/**
	 * Returns the file name at a given index
	 * @param index index
	 * @return file name or {@code null} if there is no file with that index
	 */
	public String getFileName(Integer index) {
		return filenameToIndex.inverse().get(index);
	}

	/**
	 * Encode the index to a stream
	 * @param encoder stream to write to
	 * @throws IOException for errors writing to the stream
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SOURCEFILES);
		for (int i = 0; i < leastUnusedIndex; ++i) {
			encoder.openElement(ELEM_SOURCEFILE);
			encoder.writeString(ATTRIB_NAME, filenameToIndex.inverse().get(i));
			encoder.writeSignedInteger(ATTRIB_INDEX, i);
			encoder.closeElement(ELEM_SOURCEFILE);
		}
		encoder.closeElement(ELEM_SOURCEFILES);
	}

	/**
	 * Decode an index from a stream
	 * @param decoder is the stream
	 * @throws DecoderException for errors in the encoding
	 */
	public void decode(Decoder decoder) throws DecoderException {
		int elem = decoder.openElement(ELEM_SOURCEFILES);
		while (decoder.peekElement() == ELEM_SOURCEFILE.id()) {
			decoder.openElement();
			String filename = decoder.readString(ATTRIB_NAME);
			int index = (int) decoder.readSignedInteger(ATTRIB_INDEX);
			filenameToIndex.put(filename, index);
			decoder.closeElement(ELEM_SOURCEFILE.id());
		}
		decoder.closeElement(elem);
	}

}
