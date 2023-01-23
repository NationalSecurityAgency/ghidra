package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mufom.MufomHeader;
import ghidra.app.util.bin.format.mufom.MufomHeader.MufomData;
import ghidra.app.util.bin.format.mufom.MufomHeader.MufomExternal;
import ghidra.app.util.bin.format.mufom.MufomHeader.MufomSectionDefinition;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class MufomLoader extends AbstractLibrarySupportLoader {

	private Program program;
	private Memory memory;
	private Listing listing;
	private MessageLog log;
	private MufomHeader curr;

	public MufomLoader() {

	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		MufomHeader mufom = new MufomHeader(provider, null);
		if (mufom.valid()) {
			List<QueryResult> results =
					QueryOpinionService.query(getName(), mufom.machine(), null);
			for (QueryResult result : results) {
				boolean add = true;
				if (mufom.is_little() && result.pair.getLanguageDescription().getEndian() != Endian.LITTLE) {
					add = false;
				}
				if (mufom.is_big() && result.pair.getLanguageDescription().getEndian() != Endian.BIG) {
					add = false;
				}
				if (add) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}
		return loadSpecs;
	}

	@Override
	public String getName() {
		return MufomHeader.getName();
	}

	private void createLabels() throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		MufomExternal asw3 = curr.asw3;
		Address addr = null;

		while (asw3 != null) {
			addr = getDefaultAddressSpace().getAddress(asw3.getAddress());
			if (null != addr) {
				symbolTable.createLabel(addr, asw3.getName(), null, SourceType.IMPORTED);
			}
			asw3 = asw3.next;
		}
	}

	private void fillSections() throws IOException, MemoryAccessException {
		MufomData asw5 = curr.asw5;
		Address addr = null;
		while (asw5 != null) {
			long address = asw5.getSectionAddress();
			long offset = asw5.getDataOffset();
			long length = asw5.getDataLength();

			if (address > 0) {
				addr = getDefaultAddressSpace().getAddress(address);
			}
			
			if (memory.contains(addr, addr.add(length - 1))) {
				byte[] data = curr.reader.readByteArray(offset, (int) length);
				program.getMemory().setBytes(addr, data);
				addr = addr.add(length);
			}
			asw5 = asw5.next;
		}
	}

	private void createSections(MessageLog log) throws MemoryBlockException, LockException, NotFoundException {
		MufomSectionDefinition asw2 = curr.asw2;
		MemoryBlock blockStart;
		MemoryBlock blockEnd;
		MemoryBlock blockNew;
		Address addr = null;
		long address;
		long len;

		while (asw2 != null) {
			address = asw2.getBaseAddress();
			len = asw2.getSectionLength();
			if (address >= 0 && len > 0) {
				addr = getDefaultAddressSpace().getAddress(address);
	
				blockNew = null;
				blockStart = memory.getBlock(addr);
				blockEnd = memory.getBlock(addr.add(len - 1));
	
				// There are attributes that describe if some of this should happen, but depending on when
				// the section gets added that logic may be difficult to tell.
				if (null == blockStart && null == blockEnd) {
					// No section contains this address, create a new block
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					//TODO  join if next to each other?
				} else if (null == blockStart && null != blockEnd) {
					// blockNew overlaps the end of a section
					len = addr.subtract(blockEnd.getEnd().add(1));
					addr = blockEnd.getEnd().add(1);
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					memory.join(blockEnd, blockNew);
				} else if (null != blockStart && null == blockEnd) {
					// blockNew overlaps the start of a section
					len = blockStart.getStart().subtract(addr);
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					memory.join(blockNew, blockStart);
				} else if (null != blockStart && null != blockEnd) {
					// blockNew is inside a section
				}
			}
			asw2 = asw2.next;
		}
	}

	private void load(MufomHeader mufom,Program program, TaskMonitor monitor,
			MessageLog log) throws IOException, InvalidInputException, MemoryAccessException, LockException, NotFoundException {
		this.program = program;
		this.memory = program.getMemory();
		this.listing = program.getListing();
		this.curr = mufom;
		this.log = log;

		createSections(log);
		fillSections();
		createLabels();
		//throw new IOException();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		// TODO Auto-generated method stub
		MufomHeader mufom = new MufomHeader(provider, msg -> log.appendMsg(msg));
		try {
			load(mufom, program, monitor, log);
		} catch (InvalidInputException e) {
			//
		} catch (MemoryAccessException e) {
			//
		} catch (NotFoundException e) {
			//
		} catch (LockException e) {
			//
		}
	}

	private AddressSpace getDefaultAddressSpace() {
		return program.getAddressFactory().getDefaultAddressSpace();
	}

}
