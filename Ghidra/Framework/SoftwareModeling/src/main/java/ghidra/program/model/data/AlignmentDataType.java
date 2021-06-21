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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

public class AlignmentDataType extends BuiltIn implements Dynamic {
	private final static long serialVersionUID = 1;

	private static final int MAX_LENGTH = 1024;

	public AlignmentDataType() {
		this(null);
	}

	public AlignmentDataType(DataTypeManager dtm) {
		super(null, "Alignment", dtm);
	}

	private int computeLength(MemBuffer buf) {
		int length = 0;
		try {
			byte startByte = buf.getByte(0);
			Listing listing = null;
			try {
				if (buf.getMemory() != null && buf.getMemory().getProgram() != null) {
					listing = buf.getMemory().getProgram().getListing();
				}
			}
			catch (UnsupportedOperationException exc) {
				// ignore
			}
			while (length < MAX_LENGTH) {
				byte b = buf.getByte(length);
				Address addr = buf.getAddress().add(length);
				if (listing != null && (listing.getDefinedDataAt(addr) != null ||
					listing.getInstructionAt(addr) != null)) {
					break;
				}
				if (b != startByte) {
					break;
				}
				++length;
			}
		}
		catch (MemoryAccessException e) {
			// stop counting
		}
		catch (AddressOutOfBoundsException exc) {
			// stop counting
		}
		return length > 0 ? length : -1;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new AlignmentDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "Consumes alignment/repeating bytes.";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "align";
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	@Override
	public int getLength(MemBuffer buf, int length) {
		if (length < 0) {
			length = computeLength(buf);
		}
		return length;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "align(" + length + ")";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getRepresentation(buf, settings, length);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return String.class;
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
