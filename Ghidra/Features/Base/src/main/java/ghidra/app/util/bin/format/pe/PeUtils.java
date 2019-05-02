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
package ghidra.app.util.bin.format.pe;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

public class PeUtils {

	public static Address getMarkupAddress(Program program, boolean isBinary, NTHeader ntHeader,
			int offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		if (isBinary) {
			int ptr = ntHeader.rvaToPointer(offset);
			if (ptr < 0 && offset > 0) {//directory does not appear inside a loadable section
				Msg.error(PeUtils.class, "Invalid RVA " + Integer.toHexString(offset));
				return space.getAddress(offset);
			}
			return space.getAddress(ptr);
		}
		return space.getAddress(offset + ntHeader.getOptionalHeader().getImageBase());
	}

	public static Data createData(Program program, Address addr, DataType datatype,
			MessageLog log) {
		Data existingData = program.getListing().getDefinedDataAt(addr);
		if (existingData != null) {
			DataType existingDataType = existingData.getDataType();
			if (existingDataType.isEquivalent(datatype)) {
				return existingData;
			}
		}
		try {
			program.getListing().createData(addr, datatype);
			return program.getListing().getDefinedDataAt(addr);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg("[" + program.getName() + "]: failed to create " +
				datatype.getDisplayName() + " at " + addr + ": " + e.getMessage());
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
		}
		return null;
	}

	public static void createData(Program program, Address addr, DataType datatype,
			int datatypeLength, MessageLog log) {
		try {
			program.getListing().createData(addr, datatype, datatypeLength);
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
		}
	}

}
