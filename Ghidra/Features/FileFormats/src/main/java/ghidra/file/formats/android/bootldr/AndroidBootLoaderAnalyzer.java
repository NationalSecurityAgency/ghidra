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
package ghidra.file.formats.android.bootldr;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Annotates the structures contained in an Android Boot Loader image.
 */
public class AndroidBootLoaderAnalyzer extends AbstractAnalyzer {

	public AndroidBootLoaderAnalyzer() {
		super("Android Boot Loader", "Annotates the Android Boot Loader header components",
			AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return AndroidBootLoaderConstants.isBootLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return AndroidBootLoaderConstants.isBootLoader(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		Address headerAddress = program.getMinAddress();
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), headerAddress);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		try {
			AndroidBootLoaderHeader header = new AndroidBootLoaderHeader(reader);
			DataType headerDataType = header.toDataType();
			Data headerData = program.getListing().createData(headerAddress, headerDataType);
			if (headerData == null) {
				log.appendMsg("Unable to apply header data, stopping.");
				return false;
			}
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol headerSymbol = symbolTable.getPrimarySymbol(headerAddress);
			if (headerSymbol == null) {
				symbolTable.createLabel(headerAddress, header.getMagic(), SourceType.ANALYSIS);
			}
			else {
				headerSymbol.setName(header.getMagic(), SourceType.ANALYSIS);
			}
			int runningOffset = header.getStartOffset();
			for (AndroidBootLoaderImageInfo imageInfo : header.getImageInfoList()) {
				Address address = addressSpace.getAddress(runningOffset);
				symbolTable.createLabel(address, imageInfo.getName(), SourceType.ANALYSIS);
				program.getBookmarkManager()
						.setBookmark(address, BookmarkType.ANALYSIS, "boot", imageInfo.getName());
				runningOffset += imageInfo.getSize();
			}
			return true;
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}
}
