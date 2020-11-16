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
		return dump();
	}

	/**
	 * Dumps this class.  This package-protected method is for debugging only.
	 * @return the {@link String} output.
	 */
	String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("ImageFunctionEntry------------------------------------------\n");
		builder.append(String.format("startingAddress: 0X%08X\n", startingAddress));
		builder.append(String.format("endingAddress: 0X%08X\n", endingAddress));
		builder.append(String.format("endOfPrologueAddress: 0X%08X\n", endOfPrologueAddress));
		builder.append("End ImageFunctionEntry--------------------------------------\n");
		return builder.toString();
	}

}
