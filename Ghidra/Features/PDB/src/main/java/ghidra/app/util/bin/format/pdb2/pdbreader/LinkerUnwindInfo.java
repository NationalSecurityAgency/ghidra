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
 * Linker Unwind Information that seems to be used in some XData types within {@link DebugData}.
 */
public class LinkerUnwindInfo {

	private int version; // unsigned short
	private int flags; // unsigned short
	private long dataLength; // unsigned int

	/**
	 * Returns the version.
	 * @return the version.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the flags.
	 * @return the flags.
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Returns the data length.
	 * @return the data length.
	 */
	public long getDataLength() {
		return dataLength;
	}

	/**
	 * Deserializes the {@link ImageFunctionEntry} information from a {@link PdbByteReader}
	 * @param reader the {@link PdbByteReader} from which to parse the data.
	 * @throws PdbException upon problem parsing the data.
	 */
	public void deserialize(PdbByteReader reader) throws PdbException {
		version = reader.parseUnsignedShortVal();
		flags = reader.parseUnsignedShortVal();
		dataLength = reader.parseUnsignedIntVal();
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
		builder.append("LinkerUnwindInfo--------------------------------------------\n");
		dumpInternal(builder);
		builder.append("End LinkerUnwindInfo----------------------------------------\n");
		return builder.toString();
	}

	protected void dumpInternal(StringBuilder builder) {
		builder.append(String.format("version: 0X%04X\n", version));
		builder.append(String.format("flags: 0X%04X\n", flags));
		builder.append(String.format("dataLength: 0X%08X\n", dataLength));
	}
}
