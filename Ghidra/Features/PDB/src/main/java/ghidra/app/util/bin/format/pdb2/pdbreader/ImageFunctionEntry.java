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

import java.io.*;

/**
 * Image Function Entry data seems to be the main data PData record of the {@link DebugData}.
 */
public class ImageFunctionEntry {

	private long startingAddress;
	private long endingAddress;
	private long endOfPrologueAddress;

	/**
	 * Returns the starting address.
	 * @return the starting address.
	 */
	public long getStartingAddress() {
		return startingAddress;
	}

	/**
	 * Returns the ending address.
	 * @return the ending address.
	 */
	public long getEndingAddress() {
		return endingAddress;
	}

	/**
	 * Returns the end-of-prologue address.
	 * @return the end-of-prologue address.
	 */
	public long getEndOfPrologueAddress() {
		return endOfPrologueAddress;
	}

	/**
	 * Deserializes the {@link ImageFunctionEntry} information from a {@link PdbByteReader}
	 * @param reader the {@link PdbByteReader} from which to parse the data.
	 * @throws PdbException upon problem parsing the data.
	 */
	public void deserialize(PdbByteReader reader) throws PdbException {
		startingAddress = reader.parseUnsignedIntVal();
		endingAddress = reader.parseUnsignedIntVal();
		endOfPrologueAddress = reader.parseUnsignedIntVal();
	}

	@Override
	public String toString() {
		StringWriter writer = new StringWriter();
		try {
			dump(writer);
			return writer.toString();
		}
		catch (IOException e) {
			return "Issue in " + getClass().getSimpleName() + " toString(): " + e.getMessage();
		}
	}

	/**
	 * Dumps this class to Writer.  This package-protected method is for debugging only
	 * @param writer the writer
	 * @throws IOException upon issue with writing to the writer
	 */
	void dump(Writer writer) throws IOException {
		PdbReaderUtils.dumpHead(writer, this);
		writer.write(String.format("startingAddress: 0X%08X\n", startingAddress));
		writer.write(String.format("endingAddress: 0X%08X\n", endingAddress));
		writer.write(String.format("endOfPrologueAddress: 0X%08X\n", endOfPrologueAddress));
		PdbReaderUtils.dumpTail(writer, this);
	}

}
