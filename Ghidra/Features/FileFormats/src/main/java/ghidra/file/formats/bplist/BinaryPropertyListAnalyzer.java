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
package ghidra.file.formats.bplist;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class BinaryPropertyListAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "Binary Property List (BPLIST) Annotation";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;// return canAnalyze( program );
	}

	@Override
	public String getDescription() {
		return "Annotates a Binary Property List (BPLIST).";
	}

	@Override
	public boolean canAnalyze(Program program) {
		// a binary plist does not specify it's length in the header,
		// the file determines the length.
		// therefore, a bplist must exists in it's own block
		// search through each block looking for the magic number
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (BinaryPropertyListUtil.isBinaryPropertyList(memory, block.getStart())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Memory memory = program.getMemory();
		for (MemoryBlock block : memory.getBlocks()) {
			monitor.checkCanceled();
			if (BinaryPropertyListUtil.isBinaryPropertyList(memory, block.getStart())) {
				ByteProvider provider =
					new ImmutableMemoryRangeByteProvider(memory, block.getStart(), block.getEnd());
				markup(block.getStart(), provider, program, monitor);
			}
		}
		removeEmptyFragments(program);
		return true;
	}

	private void markup(Address baseAddress, ByteProvider provider, Program program,
			TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, false /* always big */);
		try {
			BinaryPropertyListHeader header =
				markupBinaryPropertyListHeader(program, reader, baseAddress);
			BinaryPropertyListTrailer trailer =
				markupBinaryPropertyListTrailer(program, header, baseAddress);
			markupObjects(reader, program, trailer, baseAddress, monitor);
			markupOffsetTable(program, trailer, baseAddress, monitor);
		}
		finally {
			provider.close();
		}
	}

	private void markupOffsetTable(Program program, BinaryPropertyListTrailer trailer,
			Address baseAddress, TaskMonitor monitor) throws Exception {
		DataType offsetDataType = null;
		if (trailer.getOffsetSize() == 1) {
			offsetDataType = new ByteDataType();
		}
		else if (trailer.getOffsetSize() == 2) {
			offsetDataType = new WordDataType();
		}
		else if (trailer.getOffsetSize() == 4) {
			offsetDataType = new DWordDataType();
		}
		else if (trailer.getOffsetSize() == 8) {
			offsetDataType = new QWordDataType();
		}
		else {
			throw new RuntimeException("unexpected offset table element size");
		}
		Address offsetTableAddress = baseAddress.add(trailer.getOffsetTableOffset());
		Address end = offsetTableAddress.add(trailer.getObjectCount() * offsetDataType.getLength());
		ArrayDataType datatype =
			new ArrayDataType(offsetDataType, trailer.getObjectCount(), offsetDataType.getLength());
		clearListing(program, offsetTableAddress, end);
		createData(program, offsetTableAddress, datatype);
		setPlateComment(program, offsetTableAddress, "OFFSET_TABLE");
		createFragment(program, "OFFSET_TABLE", offsetTableAddress, end);
	}

	private void markupObjects(BinaryReader reader, Program program,
			BinaryPropertyListTrailer trailer, Address baseAddress, TaskMonitor monitor)
			throws Exception {
		Map<NSObject, Data> objectMap = new HashMap<NSObject, Data>();
		for (int i = 0; i < trailer.getOffsetTable().length; ++i) {
			monitor.checkCanceled();
			int objectOffset = trailer.getOffsetTable()[i];
			NSObject object = NSObjectParser.parseObject(reader, objectOffset, trailer);
			Address objectAddress = baseAddress.add(objectOffset);
			String name = BinaryPropertyListUtil.generateName(i);
			setPlateComment(program, objectAddress, name + "\n" + object.toString());
			program.getSymbolTable().createLabel(objectAddress, name, SourceType.ANALYSIS);
			DataType objectDataType = object.toDataType();
			createFragment(program, object.getType(), objectAddress,
				objectAddress.add(objectDataType.getLength()));
			clearListing(program, objectAddress, objectAddress.add(objectDataType.getLength()));
			Data objectData = createData(program, objectAddress, objectDataType);
			objectMap.put(object, objectData);
		}
		// markup the NSObjects as a second pass
		// because all need to be created first
		for (NSObject object : objectMap.keySet()) {
			monitor.checkCanceled();
			object.markup(objectMap.get(object), program, monitor);
		}
		// markup the nested PLists
		for (NSObject object : objectMap.keySet()) {
			monitor.checkCanceled();
			handleNestedBinaryPlist(object, program, objectMap.get(object), monitor);
		}
	}

	private BinaryPropertyListTrailer markupBinaryPropertyListTrailer(Program program,
			BinaryPropertyListHeader header, Address baseAddress) throws Exception {
		BinaryPropertyListTrailer trailer = header.getTrailer();
		Address trailerAddress = baseAddress.add(trailer.getTrailerIndex());
		DataType trailerDataType = trailer.toDataType();
		clearListing(program, trailerAddress, trailerAddress.add(trailerDataType.getLength()));
		createData(program, trailerAddress, trailerDataType);
		createFragment(program, trailerDataType.getName(), trailerAddress,
			trailerAddress.add(trailerDataType.getLength()));
		setPlateComment(program, trailerAddress, "Binary Property List Trailer");
		return trailer;
	}

	private BinaryPropertyListHeader markupBinaryPropertyListHeader(Program program,
			BinaryReader reader, Address baseAddress) throws Exception {
		BinaryPropertyListHeader header = new BinaryPropertyListHeader(reader);
		Address headerAddress = baseAddress.add(0x0);
		DataType headerDataType = header.toDataType();
		clearListing(program, headerAddress, headerAddress.add(headerDataType.getLength()));
		createData(program, headerAddress, headerDataType);
		createFragment(program, headerDataType.getName(), headerAddress,
			headerAddress.add(headerDataType.getLength()));
		setPlateComment(program, headerAddress, "Binary Property List Header");
		return header;
	}

	private void handleNestedBinaryPlist(NSObject object, Program program, Data objectData,
			TaskMonitor monitor) throws Exception {
		// if ( object instanceof NSData ) {// handle nested PLISTs
		// NSData data = (NSData ) object;
		//
		// Data component = objectData.getComponent(
		// objectData.getNumComponents( ) - 1 );
		//
		// ByteProvider nestedProvider = new ByteArrayProvider( data.getData( )
		// );
		//
		// if ( BinaryPropertyListUtil.isBinaryPropertyList( nestedProvider ) )
		// {
		//
		// program.getListing( ).clearCodeUnits( objectData.getMinAddress( ),
		// objectData.getMaxAddress( ), true );
		//
		// markup( program, component.getMinAddress( ), component.getMaxAddress(
		// ), monitor );
		// }
		// }
	}

	private void clearListing(Program program, Address startAddress, Address endAddress) {
		program.getListing().clearCodeUnits(startAddress, endAddress.subtract(1), true);
	}

}
