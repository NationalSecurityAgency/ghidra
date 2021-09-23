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
package ghidra.file.formats.android.dex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.file.formats.android.cdex.CDexConstants;
import ghidra.file.formats.android.cdex.CDexHeader;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public final class DexHeaderFactory {

	/**
	 * Attempts to create DEX header starting at minimum address of the program.
	 * @param program the program to use to create DEX header
	 * @return the DEX header
	 * @throws IOException should an error occur reading DEX bytes
	 */
	public final static DexHeader getDexHeader(Program program) throws IOException {
		return getDexHeader(program, program.getMinAddress());
	}

	/**
	 * Attempts to create DEX header starting at the specified address of the program.
	 * @param program the program to use to create DEX header
	 * @param address the address in the program to look for DEX header
	 * @return the DEX header
	 * @throws IOException should an error occur reading DEX bytes
	 */
	public final static DexHeader getDexHeader(Program program, Address address)
			throws IOException {
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		return getDexHeader(provider, !program.getLanguage().isBigEndian());
	}

	/**
	 * Attempts to create DEX header using the specified Byte Provider.
	 * @param provider the byte provider to use to create DEX header
	 * @param isLittleEndian true if LE, false if BE
	 * @return the DEX header
	 * @throws IOException should an error occur reading DEX bytes
	 */
	public final static DexHeader getDexHeader(ByteProvider provider, boolean isLittleEndian)
			throws IOException {
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);
		return getDexHeader(reader);
	}

	/**
	 * Attempts to create DEX header using the specified Byte Provider.
	 * NOTE: Use a new binary reader instance, where the underlying ByteProvider is
	 * based to start of DEX/CDEX.  Reading CDEX format requires lots of re-indexing.
	 * @param reader the binary reader to use to create DEX header
	 * @return the DEX header
	 * @throws IOException should an error occur reading DEX bytes
	 */
	public final static DexHeader getDexHeader(BinaryReader reader) throws IOException {
		long index = reader.getPointerIndex();
		String magic = new String(reader.readByteArray(index, 4));
		if (DexConstants.DEX_MAGIC_BASE.equals(magic)) {
			DexHeader header = new DexHeader(reader);
			header.parse(reader);
			return header;
		}
		if (CDexConstants.MAGIC.equals(magic)) {
			CDexHeader header = new CDexHeader(reader);
			header.parse(reader);
			return header;
		}
		throw new IOException("Not a recognized DEX/CDEX variant: " + magic);
	}
}
