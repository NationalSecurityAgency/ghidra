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
package ghidra.file.formats.dtb;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent a Flattened Device Tree (FDT) Reserve Entry. 
 *
 */
public class FdtReserveEntry implements StructConverter {

	private long address;
	private long size;

	FdtReserveEntry(BinaryReader reader) throws IOException {
		address = reader.readNextLong();
		size = reader.readNextLong();
	}

	/**
	 * Returns FDT Reserve Entry address.
	 * @return FDT Reserve Entry address
	 */
	public long getAddress() {
		return address;
	}

	/**
	 * Returns FDT Reserve Entry size.
	 * @return FDT Reserve Entry size
	 */
	public long getSize() {
		return size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

}
