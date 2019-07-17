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
package ghidra.file.formats.ios.dyldcache;

import ghidra.app.cmd.formats.MachoBinaryAnalysisCommand;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.DyldCacheUtils;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DyldCacheAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Address headerAddress = program.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), headerAddress);

		DyldArchitecture architecture = DyldArchitecture.getArchitecture(provider);
		if (architecture == null) {
			log.appendMsg("Invalid DYLD cache file.");
			return false;
		}

		BinaryReader reader =
			new BinaryReader(provider, architecture.getEndianness() == Endian.LITTLE);

		DyldCacheHeader header = new DyldCacheHeader(reader);

		DataType headerDataType = header.toDataType();
		Data headerData = createData(program, headerAddress, headerDataType);
		createFragment(program, headerDataType.getName(), headerData.getMinAddress(),
			headerData.getMaxAddress().add(1));

		reader.setPointerIndex(header.getImagesOffset());
		Address address = toAddr(program, header.getImagesOffset());

		for (int i = 0; i < header.getImagesCount(); ++i) {

			if (monitor.isCancelled()) {
				break;
			}

			DyldCacheImageInfo data = new DyldCacheImageInfo(reader);
			DataType dataDataType = data.toDataType();
			Data dataData = createData(program, address, dataDataType);
			createFragment(program, dataDataType.getName(), dataData.getMinAddress(),
				dataData.getMaxAddress().add(1));

			Address fileOffset = toAddr(program, data.getAddress());
			Data fileData = createData(program, fileOffset, new StringDataType());
			createFragment(program, "LibraryNames", fileData.getMinAddress(),
				fileData.getMaxAddress().add(1));

			String filePath = (String) fileData.getValue();

			Address libraryOffsetAddress =
				toAddr(program, data.getAddress() - header.getBaseAddress());

			MachoBinaryAnalysisCommand command = new MachoBinaryAnalysisCommand(
				libraryOffsetAddress, false, program.getListing().getDefaultRootModule());
			command.applyTo(program, monitor);

			setPlateComment(program, address, filePath);
			setPlateComment(program, libraryOffsetAddress, filePath);

			address = address.add(dataDataType.getLength());
		}

		updateImageBase(program, header);

		return false;
	}

	private void updateImageBase(Program program, DyldCacheHeader header) throws Exception {
		long imageBaseValue = header.getBaseAddress();
		Address imageBase = toAddr(program, imageBaseValue);
		program.setImageBase(imageBase, true);

	}

	@Override
	public boolean canAnalyze(Program program) {
		Options options = program.getOptions("Program Information");
		String format = options.getString("Executable Format", null);
		if (!BinaryLoader.BINARY_NAME.equals(format)) {
			return false;
		}
		return DyldCacheUtils.isDyldCache(program);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return DyldCacheUtils.isDyldCache(program);
	}

	@Override
	public String getDescription() {
		return "Annotates an DYLD Cache file.";
	}

	@Override
	public String getName() {
		return "DYLD Cache Annotation";
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

}
