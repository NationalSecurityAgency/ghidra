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
package ghidra.file.formats.ios.img2;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class Img2Analyzer extends FileFormatAnalyzer {

	public boolean canAnalyze(Program program) {
		try {
			return Img2Util.isIMG2(program);
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}

	public boolean getDefaultEnablement(Program program) {
		return Img2Util.isIMG2(program);
	}

	public String getDescription() {
		return "Annotates an IMG2 file.";
	}

	public String getName() {
		return "IMG2 Annotation";
	}

	public boolean isPrototype() {
		return true;
	}

	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, true);

		Img2 header = new Img2(reader);

		if (!header.getSignature().equals(Img2Constants.IMG2_SIGNATURE)) {
			log.appendMsg("Invalid Img2 file!");
			return false;
		}

		DataType headerDataType = header.toDataType();
		Data headerData = createData(program, toAddr(program, 0), headerDataType);
		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));

		changeFormatToString(headerData.getComponent(0));
		changeFormatToString(headerData.getComponent(1));

		Address dataStartAddress = headerData.getMaxAddress().add(1);
		Address dataEndAddress = dataStartAddress.add(header.getDataLen());
		try {
			createFragment(program, "DATA", dataStartAddress, dataEndAddress);
		}
		catch (Exception e) {//in case the actual program is named DATA, which is probably will be since it is the DATA section of the IMG@ file.
			createFragment(program, "DATA_" + dataStartAddress, dataStartAddress, dataEndAddress);
		}

		if (header.getDataLen() != header.getDataLenPadded()) {
			Address paddingStartAddress = dataEndAddress.add(1);
			Address paddingEndAddress =
				paddingStartAddress.add(header.getDataLenPadded() - header.getDataLen());
			createFragment(program, "PADDING", paddingStartAddress, paddingEndAddress);
		}

		removeEmptyFragments(program);

		return true;
	}

}
