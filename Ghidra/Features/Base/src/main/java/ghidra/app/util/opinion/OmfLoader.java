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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.OmfFixupRecord.Subrecord;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class OmfLoader extends AbstractLibrarySupportLoader {
	public final static String OMF_NAME = "Relocatable Object Module Format (OMF)";
	public final static long MIN_BYTE_LENGTH = 11;
	public final static long IMAGE_BASE = 0x2000; // Base offset to start loading segments
	public final static long MAX_UNINITIALIZED_FILL = 0x2000;	// Maximum zero bytes added to pad initialized segments

	private ArrayList<OmfSymbol> externsyms = null;

	/**
	 * OMF usually stores a string describing the compiler that produced it in a
	 * translator comment.  This routine maps this string to official
	 * "secondary constraint" used by the Ghidra opinion service to pick a
	 * language module for the program 
	 * @param record is the translator comment string
	 * @return the "secondary constraint"
	 */
	private String mapTranslator(String record) {
		if (record == null) {
			return null;
		}
		if (record.startsWith("Borland")) {
			return "borlandcpp";
		}
		if (record.startsWith("Delphi")) {
			return "borlanddelphi";
		}
		if (record.startsWith("CodeGear")) {
			return "codegearcpp";
		}
		return null;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		BinaryReader reader = OmfFileHeader.createReader(provider);
		if (OmfFileHeader.checkMagicNumber(reader)) {
			reader.setPointerIndex(0);
			OmfFileHeader scan;
			try {
				scan = OmfFileHeader.scan(reader, TaskMonitorAdapter.DUMMY_MONITOR, true);
			}
			catch (OmfException e) {
				throw new IOException("Bad header format: " + e.getMessage());
			}
			List<QueryResult> results = QueryOpinionService.query(getName(), scan.getMachineName(),
				mapTranslator(scan.getTranslator()));
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, IMAGE_BASE, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, IMAGE_BASE, true));
			}
		}
		return loadSpecs;
	}

	@Override
	public String getName() {
		return OMF_NAME;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		OmfFileHeader header = null;
		BinaryReader reader = OmfFileHeader.createReader(provider);
		try {
			header = OmfFileHeader.parse(reader, monitor);
			header.resolveNames();
			header.sortSegmentDataBlocks();
			OmfFileHeader.doLinking(IMAGE_BASE, header.getSegments(), header.getGroups());
		}
		catch (OmfException ex) {
			if (header == null) {
				throw new IOException("OMF File header was corrupted");
			}
			log.appendMsg("File was corrupted - leaving partial program " + provider.getName());
		}

		// We don't use the file bytes to create block because the bytes are manipulated before
		// forming the block.  Creating the FileBytes anyway in case later we want access to all
		// the original bytes.
		MemoryBlockUtils.createFileBytes(program, provider, monitor);

		int id = program.startTransaction("loading program from OMF");
		boolean success = false;
		try {
			processSegmentHeaders(reader, header, program, monitor, log);
			processExternalSymbols(header, program, monitor, log);
			processPublicSymbols(header, program, monitor, log);
			processRelocations(header, program, monitor, log);
			success = true;
		}
		catch (AddressOverflowException e) {
			throw new IOException(e);
		}
		finally {
			program.endTransaction(id, success);
		}
	}

	/**
	 * Log a (hopefully) descriptive error, if we can't process a specific relocation
	 * @param program is the Program
	 * @param log will receive the error message
	 * @param state is the relocation record that could not be processed
	 */
	private void relocationError(Program program, MessageLog log, OmfFixupRecord.FixupState state) {
		String message;
		if (state.locAddress != null) {
			message = "Unable to process relocation at " + state.locAddress + " with type 0x" +
				Integer.toHexString(state.locationType);
			program.getBookmarkManager().setBookmark(state.locAddress, BookmarkType.ERROR,
				"Relocations", message);
		}
		else {
			message = "Badly broken relocation";
		}
		log.appendMsg(message);
	}

	/**
	 * Process an relocation (FIXUPP) records and create formal Ghidra relocation objects
	 * @param header is the file header for the program
	 * @param program is the Program
	 * @param monitor is checked for cancellation
	 * @param log receives error messages
	 */
	private void processRelocations(OmfFileHeader header, Program program, TaskMonitor monitor,
			MessageLog log) {
		ArrayList<OmfFixupRecord> fixups = header.getFixups();
		OmfFixupRecord.FixupState state =
			new OmfFixupRecord.FixupState(header, externsyms, program.getLanguage());
		DataConverter converter = DataConverter.getInstance(!header.isLittleEndian());

		for (OmfFixupRecord fixup : fixups) {
			state.currentFixupRecord = fixup;
			Subrecord[] subrecs = fixup.getSubrecords();
			Memory memory = program.getMemory();
			for (Subrecord subrec : subrecs) {
				if (monitor.isCancelled()) {
					break;
				}

				if (subrec.isThread()) {
					((OmfFixupRecord.ThreadSubrecord) subrec).updateState(state);
				}
				else {
					long finalvalue = -1;
					byte[] origbytes = null;

					try {
						OmfFixupRecord.FixupSubrecord fixsub =
							(OmfFixupRecord.FixupSubrecord) subrec;
						state.clear();
						fixsub.resolveFixup(state);
						if (state.targetState == -1 || state.locAddress == null) {
							relocationError(program, log, state);
							continue;
						}

						switch (state.locationType) {
							case 0: // Low-order byte
								origbytes = new byte[1];
								memory.getBytes(state.locAddress, origbytes);
								finalvalue = state.targetState;
								if (state.M) {
									finalvalue += origbytes[0];
								}
								else {
									finalvalue -= (state.locAddress.getOffset() + 1);
								}
								memory.setByte(state.locAddress, (byte) finalvalue);
								break;
							case 1: // 16-bit offset
							case 5: // 16-bit loader-resolved offset (treated same as 1)
								origbytes = new byte[2];
								memory.getBytes(state.locAddress, origbytes);
								finalvalue = state.targetState;
								if (state.M) {
									finalvalue += converter.getShort(origbytes);
								}
								else {
									finalvalue -= (state.locAddress.getOffset() + 2);
								}
								memory.setShort(state.locAddress, (short) finalvalue);
								break;
							// case 2: // 16-bit base -- logical segment base (selector)
							// case 3: // 32-bit Long pointer (16-bit base:16-bit offset
							case 4: // High-order byte (high byte of 16-bit offset)
							case 9: // 32-bit offset
							case 13: // 32-bit loader-resolved offset (treated same as 9)
								origbytes = new byte[4];
								memory.getBytes(state.locAddress, origbytes);
								finalvalue = state.targetState;
								if (state.M) {
									finalvalue += converter.getInt(origbytes);
								}
								else {
									finalvalue -= (state.locAddress.getOffset() + 4);
								}
								memory.setInt(state.locAddress, (int) finalvalue);
								break;
							// case 11: // 48-bit pointer (16-bit base:32-bit offset)
							default:
								log.appendMsg("Unsupported relocation type " +
									Integer.toString(state.locationType) + " at 0x" +
									Long.toHexString(state.locAddress.getOffset()));
								break;
						}
					}
					catch (MemoryAccessException e) {
						relocationError(program, log, state);
						continue;
					}
					catch (OmfException e) {
						relocationError(program, log, state);
						continue;
					}
					long[] values = new long[1];
					values[0] = finalvalue;
					program.getRelocationTable().add(state.locAddress, state.locationType, values,
						origbytes, null);
				}
			}
		}
	}

	/**
	 * Run through the OMF segments an produce Ghidra memory blocks.
	 * Most segments cause an initialized block to be created, but if a segment
	 * consists only of a string of zero bytes, as described by a compact LIDATA record,
	 * an uninitialized block is created.
	 * @param reader is a reader for the underlying file
	 * @param header is the OMF file header
	 * @param program is the Program
	 * @param mbu is the block creation utility
	 * @param monitor is checked for cancellation
	 * @param log receives error messages
	 * @throws AddressOverflowException if the underlying data stream causes an address to wrap
	 * @throws IOException for problems accessing the OMF file through the reader
	 */
	private void processSegmentHeaders(BinaryReader reader, OmfFileHeader header, Program program,
			TaskMonitor monitor, MessageLog log) throws AddressOverflowException, IOException {
		monitor.setMessage("Process segments...");

		final Language language = program.getLanguage();

		ArrayList<OmfSegmentHeader> segments = header.getSegments();
//		int sectionNumber = 0;
		for (OmfSegmentHeader segment : segments) {
//			++sectionNumber;
			if (monitor.isCancelled()) {
				break;
			}

			//		if (segment.hasIteratedData() && segment.hasEnumeratedData())
			//			throw new IOException("OMF segment has both iterated and enumerated data blocks");
			MemoryBlock block = null;

			final long segmentSize = segment.getSegmentLength();

			Address segmentAddr = segment.getAddress(language);

			if (segmentSize == 0) {
				// don't create a block...just log that we've seen the segment
				block = program.getMemory().getBlock(segmentAddr);
				log.appendMsg("Empty Segment: " + segment.getName());
			}
			else if (segment.hasNonZeroData()) {
				block = MemoryBlockUtils.createInitializedBlock(program, false, segment.getName(),
					segmentAddr, segment.getRawDataStream(reader, log), segmentSize,
					"Address:0x" + Long.toHexString(segmentAddr.getOffset()) + " " + "Size:0x" +
						Long.toHexString(segmentSize),
					null/*source*/, segment.isReadable(), segment.isWritable(),
					segment.isExecutable(), log, monitor);
				if (block != null) {
					log.appendMsg(
						"Created Initialized Block: " + segment.getName() + " @ " + segmentAddr);
				}
			}
			else {
				block = MemoryBlockUtils.createUninitializedBlock(program, false, segment.getName(),
					segmentAddr, segmentSize,
					"Address:0x" + Long.toHexString(segmentAddr.getOffset()) + " " + "Size:0x" +
						Long.toHexString(segmentSize),
					null/*source*/, segment.isReadable(), segment.isWritable(),
					segment.isExecutable(), log);
				if (block != null) {
					log.appendMsg(
						"Created Uninitialized Block: " + segment.getName() + " @ " + segmentAddr);
				}
			}
		}
	}

	/**
	 * Locate the start of a free range of memory (for holding external symbols)
	 * by finding an Address beyond any memory block in the program
	 * @param program is the Program
	 * @return the starting address of the free region
	 */
	private Address findFreeAddress(Program program) {
		Memory memory = program.getMemory();
		// Don't consider overlay blocks for max addr
		Address maxAddr = memory.getMinAddress();
		if (maxAddr == null) {
			return null;
		}
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			// get the physical address in case it is an overlay address
			Address blockEnd = block.getEnd().getPhysicalAddress();
			if (blockEnd.compareTo(maxAddr) > 0) {
				maxAddr = blockEnd;
			}
		}

		// Always Align the fake External Address Space
		Address externAddress = null;
		long newOffset = (maxAddr.getOffset() + 0x1000) & 0xfffffffffffff000L;
		externAddress = maxAddr.getNewAddress(newOffset);
		return externAddress;
	}

	/**
	 * Process any public symbol records and produce corresponding Ghidra symbols
	 * @param header is the file header for the program
	 * @param program is the Program
	 * @param monitor is checked for cancellations
	 * @param log receives any error messages
	 */
	private void processPublicSymbols(OmfFileHeader header, Program program, TaskMonitor monitor,
			MessageLog log) {
		SymbolTable symbolTable = program.getSymbolTable();

		ArrayList<OmfSymbolRecord> symbols = header.getPublicSymbols();
		ArrayList<OmfSegmentHeader> segments = header.getSegments();
		ArrayList<OmfGroupRecord> groups = header.getGroups();
		Language language = program.getLanguage();

		monitor.setMessage("Creating Public Symbols");

		for (OmfSymbolRecord symbolrec : symbols) {
			if (monitor.isCancelled()) {
				break;
			}
			Address addrBase = null;
			if (symbolrec.getSegmentIndex() != 0) {
				// TODO: What does it mean if both the segment and group index are non-zero?
				//     Is the segment index group relative?
				//     For now we assume if a segment index is present, we don't need the group index
				OmfSegmentHeader baseSegment = segments.get(symbolrec.getSegmentIndex() - 1);
				addrBase = baseSegment.getAddress(language);
			}
			else if (symbolrec.getGroupIndex() != 0) {
				OmfGroupRecord baseGroup = groups.get(symbolrec.getGroupIndex() - 1);
				addrBase = baseGroup.getAddress(language);
			}
			else { // Absolute address
					// The base frame is ignored by most linkers
				addrBase = language.getDefaultSpace().getAddress(0);
			}

			int numSymbols = symbolrec.numSymbols();
			for (int i = 0; i < numSymbols; ++i) {
				OmfSymbol symbol = symbolrec.getSymbol(i);
				Address address = addrBase.add(symbol.getOffset());
				symbol.setAddress(address);

				createSymbol(symbol, address, symbolTable, log);
			}
		}
	}

	/**
	 * Create an OMF symbol in the program
	 * @param symbol is the symbol record
	 * @param address is the resolved address for the symbol
	 * @param symbolTable is the table to hold the symbol
	 * @param log is used to log error messages
	 * @return true if there are no errors creating the symbol
	 */
	private boolean createSymbol(OmfSymbol symbol, Address address, SymbolTable symbolTable,
			MessageLog log) {
		Symbol existingSym = symbolTable.getPrimarySymbol(address);
		String name = symbol.getName();
		Symbol sym = symbolTable.getGlobalSymbol(name, address);

		if (sym == null) {
			try {
				sym = symbolTable.createLabel(address, name, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg("Unable to create symbol " + symbol.getName() + " at 0x" +
					Long.toHexString(address.getOffset()));
				return false;
			}
		}
		if (existingSym == null || !existingSym.isPrimary()) {
			sym.setPrimary();
		}
		return true;
	}

	/**
	 * Process any external symbol records and create the corresponding Ghidra symbols.
	 * Build an external memory block to hold them if necessary
	 * @param header is the file header for the program
	 * @param program is the Program
	 * @param monitor is checked for cancellation
	 * @param log receives error messages
	 */
	private void processExternalSymbols(OmfFileHeader header, Program program, TaskMonitor monitor,
			MessageLog log) {

		ArrayList<OmfExternalSymbol> symbolrecs = header.getExternalSymbols();
		if (symbolrecs.size() == 0) {
			return;
		}

		Address externalAddress = findFreeAddress(program);
		if (externalAddress == null) {
			log.appendMsg("Serious problem, there is no memory at all for symbols!");
			return;
		}
		Address externalAddressStart = externalAddress;
		externsyms = new ArrayList<>();

		SymbolTable symbolTable = program.getSymbolTable();
		Language language = program.getLanguage();

		monitor.setMessage("Creating External Symbols");

		for (OmfExternalSymbol symbolrec : symbolrecs) {
			OmfSymbol[] symbols = symbolrec.getSymbols();
			// TODO: Check instanceof OmfComdefRecord
			for (OmfSymbol symbol : symbols) {
				if (monitor.isCancelled()) {
					break;
				}
				Address address = null;
				if (symbol.getSegmentRef() != 0) { // Look for special Borland segment symbols
					OmfSegmentHeader segment =
						header.getExtraSegments().get(symbol.getSegmentRef() - 1);
					address = segment.getAddress(language);
					symbol.setAddress(address);
					externsyms.add(symbol);
					createSymbol(symbol, address, symbolTable, log);
				}
				else {
					address = externalAddress;
					symbol.setAddress(address);
					externsyms.add(symbol);
					if (createSymbol(symbol, address, symbolTable, log)) {
						externalAddress = externalAddress.add(16);
					}
				}

			}
		}
		createExternalBlock(program, log, externalAddress, externalAddressStart);
	}

	/**
	 * If necessary, create an external block to hold external symbols for this file 
	 * @param program is the program representing the file
	 * @param log for error messages
	 * @param externalAddress is the address of the first byte of the external block
	 * @param externalAddressStart is the address of the last byte (+1)
	 */
	private void createExternalBlock(Program program, MessageLog log, Address externalAddress,
			Address externalAddressStart) {
		//create an artificial block for the external symbols
		if (!externalAddressStart.equals(externalAddress)) {
			long size = externalAddress.subtract(externalAddressStart);
			try {
				MemoryBlock block = program.getMemory()
						.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME,
							externalAddressStart, size, false);

				// assume any value in external is writable.
				block.setWrite(true);

				Address current = externalAddressStart;
				while (current.compareTo(externalAddress) < 0) {
					createUndefined(program.getListing(), program.getMemory(), current,
						externalAddress.getAddressSpace().getPointerSize());
					current = current.add(externalAddress.getAddressSpace().getPointerSize());
				}
			}
			catch (Exception e) {
				log.appendMsg("Error creating external memory block: " + " - " + e.getMessage());
			}
		}
	}

	/**
	 * Create undefined data at a specific address in the program
	 * @param listing is the Program listing
	 * @param memory is the Program Memory
	 * @param addr is the Address of the data
	 * @param size is the number of bytes in the data
	 * @return the new created Data object
	 * @throws CodeUnitInsertionException if the new data conflicts with another object
	 * @throws DataTypeConflictException if the data-type cannot be created
	 */
	private Data createUndefined(Listing listing, Memory memory, Address addr, int size)
			throws CodeUnitInsertionException, DataTypeConflictException {
		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		DataType undefined = Undefined.getUndefinedDataType(size);
		return listing.createData(addr, undefined);
	}
}
