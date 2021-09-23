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
package ghidra.file.formats.android.oat;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

public class OatExecAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Android OATEXEC Format";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Analyzes the Android OAT executable (oatexec) section of this program.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		//return OatConstants.isOAT(program);
		return false;
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		OatHeader header = null;
		try {
			BinaryReader reader = OatUtilities.getBinaryReader(program);
			header = OatHeaderFactory.newOatHeader(reader);
			OatHeaderFactory.parseOatHeader(header, program, reader, monitor, log);
		}
		catch (UnsupportedOatVersionException e) {
			log.appendMsg(e.getMessage());
			return false;
		}
		monitor.setMessage("OAT Version: " + header.getVersion());

		Symbol oatExecSymbol = OatUtilities.getOatExecSymbol(program);
		if (oatExecSymbol == null) {
			log.appendMsg(
				"Unable to locate " + OatConstants.SYMBOL_OAT_EXEC + " symbol, skipping...");
			return true;
		}
		Address address = oatExecSymbol.getAddress();

		Symbol oatLastWordSymbol = OatUtilities.getOatLastWordSymbol(program);
		program.getListing()
				.clearCodeUnits(oatLastWordSymbol.getAddress(), oatLastWordSymbol.getAddress(),
					true);

		//TODO adjust start position based on OatHeader values being set, such as "interpreter_to_interpreter_bridge_offset_"

		monitor.setProgress(0);
		monitor.setMaximum(oatLastWordSymbol.getAddress().subtract(address));
		try {
			while (true) {
				monitor.checkCanceled();
				monitor.setProgress(address.subtract(oatExecSymbol.getAddress()));

				if (oatLastWordSymbol.getAddress().compareTo(address) <= 0) {
					break;
				}

				ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
				BinaryReader reader =
					new BinaryReader(provider, !program.getLanguage().isBigEndian());

				OatQuickMethodHeader quickMethodHeader = OatQuickMethodHeaderFactory
						.getOatQuickMethodHeader(reader, header.getVersion());
				DataType dataType = quickMethodHeader.toDataType();
				createData(program, address, dataType);

				address = address.add(dataType.getLength());

				//TODO disassemble, restricted to, the CODESIZE amount of bytes.
				//DisassembleCommand cmd = new DisassembleCommand( address, null, true );
				//cmd.applyTo( program );
				//createFunction( program, address );

				address = address.add(quickMethodHeader.getCodeSize());
				address = align(address);
			}
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * Returns the address aligned to 0x10 bytes.
	 * 
	 * TODO how is alignment determined??? it seems to vary across files.
	 */
	private Address align(Address address) {
		int alignmentValue = 0x8;
		long offset = address.getOffset();
		if (offset % alignmentValue == 0) {
			return address;
		}
		long value = alignmentValue - (offset % alignmentValue);
		return address.getNewAddress(offset + value);
	}

}
