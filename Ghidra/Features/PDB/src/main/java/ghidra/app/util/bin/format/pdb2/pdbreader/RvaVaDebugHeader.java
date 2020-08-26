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

import java.math.BigInteger;

/**
 * A debug header that is known (others may be known in the future) to be used for PData and XData
 * within the {@link DebugData} class.
 */
public class RvaVaDebugHeader extends DebugHeader {

	private long relativeVirtualAddressDataBase;
	private BigInteger virtualAddressImageBase;
	private long unsignedIntReserved1;
	private long unsignedIntReserved2;

	/**
	 * Returns the relative virtual address data base.
	 * @return the relative virtual address data base.
	 */
	public long getRelativeVirtualAddressDataBase() {
		return relativeVirtualAddressDataBase;
	}

	/**
	 * Returns the virtual address image base.
	 * @return the virtual address image base.
	 */
	public BigInteger getVirtualAddressImageBase() {
		return virtualAddressImageBase;
	}

	/**
	 * Returns the reserved1 unsigned int stored in a long.
	 * @return the reserved1 unsigned int stored in a long.
	 */
	public long getReserved1() {
		return unsignedIntReserved1;
	}

	/**
	 * Returns the reserved2 unsigned int stored in a long.
	 * @return the reserved2 unsigned int stored in a long.
	 */
	public long getReserved2() {
		return unsignedIntReserved2;
	}

	/**
	 * Deserializes the {@link RvaVaDebugHeader} information from a {@link PdbByteReader}
	 * @param reader the {@link PdbByteReader} from which to parse the data.
	 * @throws PdbException upon problem parsing the data.
	 */
	@Override
	public void deserialize(PdbByteReader reader) throws PdbException {
		super.deserialize(reader);
		relativeVirtualAddressDataBase = reader.parseUnsignedIntVal();
		virtualAddressImageBase = reader.parseUnsignedLongVal();
		unsignedIntReserved1 = reader.parseUnsignedIntVal();
		unsignedIntReserved2 = reader.parseUnsignedIntVal();
	}

	@Override
	String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("RvaVaDebugHeader--------------------------------------------\n");
		dumpInternal(builder);
		builder.append("End RvaVaDebugHeader----------------------------------------\n");
		return builder.toString();
	}

	@Override
	protected void dumpInternal(StringBuilder builder) {
		super.dumpInternal(builder);
		builder.append(String.format("relativeVirtualAddressDataBase: 0X%08X\n",
			relativeVirtualAddressDataBase));
		builder.append(
			String.format("virtualAddressImageBase: 0X%016X\n", virtualAddressImageBase));
		builder.append(String.format("unsignedIntReserved1: 0X%08X\n", unsignedIntReserved1));
		builder.append(String.format("unsignedIntReserved2: 0X%08X\n", unsignedIntReserved2));
	}

}
