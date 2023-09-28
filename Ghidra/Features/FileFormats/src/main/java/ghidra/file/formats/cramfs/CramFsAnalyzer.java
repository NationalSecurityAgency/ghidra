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
package ghidra.file.formats.cramfs;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CramFsAnalyzer extends AbstractAnalyzer {
	// Seen offsets plus the count of how many times seen. Should only be 1
	// for each file inode, if 2 inodes share data space and have same contents.

	public CramFsAnalyzer() {
		super("CramFS Analyzer", "Annotates CramFS binaries", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			Options options = program.getOptions(Program.PROGRAM_INFO);
			String format = options.getString("Executable Format", null);
			if (!BinaryLoader.BINARY_NAME.equals(format)) {
				return false;
			}
			Language language = program.getLanguage();
			if (language.getProcessor() == Processor.findOrPossiblyCreateProcessor("DATA") &&
				!language.isBigEndian()) {
				return false;
			}
			int magic = program.getMemory().getInt(program.getMinAddress());
			return magic == CramFsConstants.MAGIC;
		}
		catch (MemoryAccessException e) {
			//Ignore
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Address minAddress = program.getMinAddress();
		boolean isLE = !program.getLanguage().isBigEndian();

		try (ByteProvider provider = new MemoryByteProvider(program.getMemory(), minAddress)) {
			BinaryReader reader = new BinaryReader(provider, isLE);
			CramFsSuper cramFsSuper = new CramFsSuper(reader);
			DataType dataType = cramFsSuper.toDataType();
			program.getListing().createData(minAddress, dataType);
			program.getListing()
					.setComment(minAddress, CodeUnit.PLATE_COMMENT,
						cramFsSuper.getRoot().toString());
			int offset = cramFsSuper.getRoot().getOffsetAdjusted();

			for (int i = 0; i < cramFsSuper.getFsid().getFiles() - 1; i++) {

				monitor.checkCancelled();
				reader.setPointerIndex(offset);
				Address inodeAddress = minAddress.add(offset);
				CramFsInode newInode = new CramFsInode(reader);

				if (newInode.isFile()) {
					Address inodeDataAddress = minAddress.add(newInode.getOffsetAdjusted());
					program.getListing()
							.setComment(inodeDataAddress, CodeUnit.PLATE_COMMENT,
								newInode.getName() + " Data/Bytes\n");
				}

				DataType inodeDataType = newInode.toDataType();
				program.getListing().createData(inodeAddress, inodeDataType);

				program.getListing()
						.setComment(inodeAddress, CodeUnit.PLATE_COMMENT,
							newInode.getName() + "\n" + newInode.toString());

				offset += inodeDataType.getLength();
			}
		}
		catch (Exception e) {
			log.appendException(e);
			return false;
		}

		return true;
	}
}
