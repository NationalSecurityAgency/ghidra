/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class AoutHeader implements StructConverter {
	public final static int SIZEOF = 28;

	protected short    magic;        // magic value - machine specific
	protected short    vstamp;       // version stamp
	protected int      tsize;        // text size in bytes
	protected int      dsize;        // initialized data size in bytes
	protected int      bsize;        // uninitialized data size in bytes
	protected int      entry;        // entry point 
	protected int      text_start;   // base of text used for this file
	protected int      data_start;   // base of data used for this file

	AoutHeader(BinaryReader reader) throws IOException {
		magic       = reader.readNextShort();
		vstamp      = reader.readNextShort();
		tsize       = reader.readNextInt();
		dsize       = reader.readNextInt();
		bsize       = reader.readNextInt();
		entry       = reader.readNextInt();
		text_start  = reader.readNextInt();
		data_start  = reader.readNextInt();
	}

	public short getMagic() {
		return magic;
	}

	public short getVersionStamp() {
		return vstamp;
	}

	public int getTextSize() {
		return tsize;
	}

	public int getInitializedDataSize() {
		return dsize;
	}

	public int getUninitializedDataSize() {
		return bsize;
	}

	public int getEntry() {
		return entry;
	}

	public int getTextStart() {
		return text_start;
	}

	public int getInitializedDataStart() {
		return data_start;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(AoutHeader.class);
	}
}
