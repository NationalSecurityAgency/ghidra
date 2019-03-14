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
package ghidra.file.formats.ios.apple8900;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class Apple8900Analyzer extends FileFormatAnalyzer {

	public boolean canAnalyze(Program program) {
		return Apple8900Util.is8900(program);
	}

	public boolean getDefaultEnablement(Program program) {
		return Apple8900Util.is8900(program);
	}

	public String getDescription() {
		return "Annotates an Apple 8900 file.";
	}

	public String getName() {
		return "Apple 8900 Annotation";
	}

	public boolean isPrototype() {
		return true;
	}

	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		monitor.setMessage("Processing Apple 8900 header...");

		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, true);

		Apple8900Header header = new Apple8900Header(reader);

		if (!header.getMagic().equals(Apple8900Constants.MAGIC)) {
			log.appendMsg("Invalid 8900 file!");
			return false;
		}

		DataType headerDataType = header.toDataType();
		Data headerData = createData(program, toAddr(program, 0), headerDataType);
		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));

		Address dataStart = toAddr(program, 0x800);
		Address dataEnd = toAddr(program, 0x800 + header.getSizeOfData());
		createFragment(program, "Data", dataStart, dataEnd);

		Address footerSigStart = toAddr(program, 0x800 + header.getFooterSignatureOffset());
		Address footerSigEnd = toAddr(program, 0x800 + header.getFooterCertificateOffset());
		createFragment(program, "FooterSig", footerSigStart, footerSigEnd);

		Address footerCertStart = toAddr(program, 0x800 + header.getFooterCertificateOffset());
		Address footerCertEnd =
			toAddr(program,
				0x800 + header.getFooterCertificateOffset() + header.getFooterCertificateLength());
		createFragment(program, "FooterCert", footerCertStart, footerCertEnd);

		removeEmptyFragments(program);

		return true;
	}

}
