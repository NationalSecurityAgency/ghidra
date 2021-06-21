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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;

/**
 * Manages Address/Section/Segment-related PDB items.
 * Has method for providing real addresses.
 */
public class PdbAddressManager {

	// This could be a valid address for the program, but we are using it as a flag.  We return
	// it to designate that an address is an external address, and we use it outside of this class
	// to test for it being an external address. These marker addresses should never be used
	// for symbol creation.
	static final Address EXTERNAL_ADDRESS = AddressSpace.EXTERNAL_SPACE.getAddress(1);
	static final Address ZERO_ADDRESS = AddressSpace.EXTERNAL_SPACE.getAddress(0);
	static final Address BAD_ADDRESS = Address.NO_ADDRESS;

	//==============================================================================================
	private Map<Integer, Long> realAddressesBySection;
	private List<SegmentMapDescription> segmentMapList;
	private List<ImageSectionHeader> imageSectionHeaders;
	private SortedMap<Long, Long> omapFromSource;
	private List<PeCoffGroupMsSymbol> memoryGroupRefinement;
	private List<PeCoffSectionMsSymbol> memorySectionRefinement;
	// private List<SegmentInfo> allSegmentsInfo;

	// Map of Address by symbol name... if a name has appeared more than once, then the Address
	// is written with Address.NO_ADDRESS to indicate that the name is found at more than one
	// address (not unique from the perspective we need of being able to map PDB addresses to
	// possibly different addresses (possibly from an application of another PDB with accurate
	// public or "unique" symbols).  Originally, we were only going to use symbols with mangled
	// names, but opened this up to a wider field of symbol names.
	private Map<String, Address> addressByPreExistingSymbolName;
	// Since we are already visiting all existing symbols, and since it will be quicker to do in
	// one pass than to continually request the primary symbol at a particular address (as we
	// are also adding more symbols), we will get an initial snapshot of what symbol is primary
	// at any particular address before we start adding more.
	private Map<Address, Symbol> primarySymbolByAddress;

	private Map<Address, Address> remapAddressByAddress;

	private PdbApplicator applicator;
	private Address imageBase;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Manager
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param imageBase Address from which all other addresses are based.
	 * @throws PdbException If Program is null;
	 */
	PdbAddressManager(PdbApplicator applicator, Address imageBase) throws PdbException {
		Objects.requireNonNull(applicator, "applicator may not be null");
		Objects.requireNonNull(imageBase, "imageBase may not be null");
		this.applicator = applicator;
		this.imageBase = imageBase;
		realAddressesBySection = new HashMap<>();
		memoryGroupRefinement = new ArrayList<>();
		memorySectionRefinement = new ArrayList<>();
		// TODO allSegmentInfo might go away if we use ImageSectionHeader. Under investigation.
//		allSegmentsInfo = new ArrayList<>();
		addressByPreExistingSymbolName = new HashMap<>();
		primarySymbolByAddress = new HashMap<>();
		determineMemoryBlocks();
//		determineMemoryBlocks_orig();
		mapPreExistingSymbols();
		createAddressRemap();
	}

	/**
	 * Returns the Address for the given symbol.  If the {@link PdbApplicatorOptions}
	 * Address Remap option is turned on is turned on, it will attempt to map the address to a
	 * new address in the current program.
	 * @param symbol The {@link AddressMsSymbol}
	 * @return The Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program.
	 */
	Address getAddress(AddressMsSymbol symbol) {
		return getAddress(symbol.getSegment(), symbol.getOffset());
	}

	/**
	 * Returns the Address for the given section and offset.  If the {@link PdbApplicatorOptions}
	 * Address Remap option is turned on is turned on, it will attempt to map the address to a
	 * new address in the current program.
	 * @param segment The segment
	 * @param offset The offset
	 * @return The Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program.
	 */
	Address getAddress(int segment, long offset) {
		Address address = getRawAddress(segment, offset);
		if (applicator.getPdbApplicatorOptions().remapAddressUsingExistingPublicSymbols()) {
			return getRemapAddressByAddress(address);
		}
		return address;
	}

	/**
	 * Returns the Address for the given section and offset.  If the {@link PdbApplicatorOptions}
	 * Address Remap option is turned on is turned on, it will attempt to map the address to a
	 * new address in the current program.
	 * @param symbol The {@link AddressMsSymbol}
	 * @return The Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program.
	 */
	Address getRawAddress(AddressMsSymbol symbol) {
		return getRawAddress(symbol.getSegment(), symbol.getOffset());
	}

	/**
	 * Returns the Address for the given section and offset.  Will attempt to map the address
	 * to a new address if the {@link PdbApplicatorOptions}
	 * @param segment The segment
	 * @param offset The offset
	 * @return The Address, which can be {@code Address.NO_ADDRESS} if invalid or
	 * {@code Address.EXTERNAL_ADDRESS} if the address is external to the program.
	 */
	Address getRawAddress(int segment, long offset) {
		if (segment < 0) {
			return BAD_ADDRESS;
		}
		Long relativeVirtualAddress = null;
		if (imageSectionHeaders != null) {
			if (segment > imageSectionHeaders.size() + 1) {
				return BAD_ADDRESS;
			}
			else if (segment == 0 || segment == imageSectionHeaders.size() + 1) {
				// External address.
				return EXTERNAL_ADDRESS;
			}
			relativeVirtualAddress =
				imageSectionHeaders.get(segment - 1).getVirtualAddress() + offset;
			relativeVirtualAddress = applyOMap(relativeVirtualAddress);
			if (relativeVirtualAddress == null) {
				return BAD_ADDRESS;
			}
			if (relativeVirtualAddress == 0) {
				return ZERO_ADDRESS;
			}
		}
		else {
			// TODO: need to verify use of segments here!
			if (segment > segmentMapList.size() + 1) {
				return BAD_ADDRESS;
			}
			else if (segment == 0 || segment == segmentMapList.size() + 1) {
				// External address.
				return EXTERNAL_ADDRESS;
			}
			// TODO: Need to verify. Guessing at the moment
			relativeVirtualAddress = segmentMapList.get(segment - 1).getSegmentOffset();
		}

		return imageBase.add(relativeVirtualAddress);
	}

	private Long applyOMap(Long relativeVirtualAddress) {
		if (omapFromSource == null) {
			return relativeVirtualAddress;
		}
		// NOTE: Original map entries are 32-bit values zero-extended to a java long (64-bits)
		SortedMap<Long, Long> headMap = omapFromSource.headMap(relativeVirtualAddress + 1);
		if (headMap.isEmpty()) {
			return null;
		}
		long from = headMap.lastKey();
		long to = headMap.get(from);
		if (to == 0) {
			return 0L;
		}
		return to + (relativeVirtualAddress - from);
	}

	/**
	 * Returns the Address of an existing symbol for the query address, where the mapping is
	 * derived by using a the address of a PDB symbol as the key and finding the address of
	 * a symbol in the program of the same "unique" name. This is accomplished using public
	 * mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @return the remapAddress
	 */
	Address getRemapAddressByAddress(Address address) {
		return remapAddressByAddress.getOrDefault(address, address);
	}

	/**
	 * Returns the primary symbol for the address, as determined at the start of PDB processing
	 * before apply any PDB symbols.
	 * @param address the {@link Address}
	 * @return the primary symbol
	 */
	Symbol getPrimarySymbol(Address address) {
		return primarySymbolByAddress.get(address);
	}

	/**
	 * Indicate to the {@link PdbAddressManager} that a new symbol with the given name has the
	 * associated address.  This allows the PdbAddressManager to create and organize the
	 * re-mapped address and supply them.  Also returns the address of the pre-existing symbol
	 * of the same name if the name was unique, otherwise null if it didn't exist or wasn't
	 * unique.
	 * @param name the symbol name
	 * @param address its associated address
	 * @return the {@link Address} of existing symbol or null
	 */
	Address witnessSymbolNameAtAddress(String name, Address address) {
		Address existingAddress = getAddressByPreExistingSymbolName(name);
		putRemapAddressByAddress(address, existingAddress);
		return existingAddress;
	}

	/**
	 * Method for callee to set the real address for the section.
	 * @param sectionNum the section number
	 * @param realAddress The Address
	 */
	void putRealAddressesBySection(int sectionNum, long realAddress) {
		realAddressesBySection.put(sectionNum, realAddress);
	}

	/**
	 * Method for callee to add a Memory Group symbol to the Memory Group list.
	 * @param symbol the symbol.
	 */
	void addMemoryGroupRefinement(PeCoffGroupMsSymbol symbol) {
		memoryGroupRefinement.add(symbol);
	}

	/**
	 * Method for callee to add a Memory Section symbol to the Memory Section list.
	 * @param symbol the symbol.
	 */
	void addMemorySectionRefinement(PeCoffSectionMsSymbol symbol) {
		memorySectionRefinement.add(symbol);
	}

	/**
	 * Dumps memory section refinement to log.
	 * @throws CancelledException Upon user cancellation
	 */
	void logReport() throws CancelledException {
		logMemorySectionRefinement();
		logMemoryGroupRefinement();
	}

	//==============================================================================================
	//==============================================================================================
	// TODO: this class might go away if we use ImageSectionHeaders directly.
	private class SegmentInfo {
		private Address start;
		private long length;

		SegmentInfo(Address startIn, long lengthIn) {
			start = startIn;
			length = lengthIn;
		}

		public Address getStartAddress() {
			return start;
		}

		public long getLength() {
			return length;
		}
	}

//	private void determineMemoryBlocks_orig() {
//		// Set section/segment 0 to image base. (should be what is header), but what is its size?
//		// TODO... made up size for now... is there something else?  We could put null instead.
//		// For now, the method that reads this information might report EXTERNAL instead of
//		// trying to use this.
//		long segmentZeroLength = 0x7fffffff;
//		allSegmentsInfo.add(new SegmentInfo(imageBase, segmentZeroLength));
//		PdbDebugInfo dbi = applicator.getPdb().getDebugInfo();
//		if (dbi instanceof PdbNewDebugInfo) {
//			DebugData debugData = ((PdbNewDebugInfo) dbi).getDebugData();
//			List<ImageSectionHeader> imageSectionHeaders = debugData.getImageSectionHeaders();
//			for (ImageSectionHeader imageSectionHeader : imageSectionHeaders) {
//				long virtualAddress = imageSectionHeader.getVirtualAddress();
//				// TODO: not sure when unionPAVS is physical address vs. virtual size.  Perhaps
//				// it keys off whether virtualAddress is not some special value such as
//				// 0x00000000 or 0xffffffff.
//				long size = imageSectionHeader.getUnionPAVS();
//				allSegmentsInfo.add(new SegmentInfo(imageBase.add(virtualAddress), size));
//			}
//		}
//		// else instance of PdbDebugInfo; TODO: what can we do here?
//		// Maybe get information from the program itself.
//
//		// TODO: what should we do with these? Not doing anything at the moment
//		AbstractPdb pdb = applicator.getPdb();
//		List<SegmentMapDescription> segmentMapList = pdb.getDebugInfo().getSegmentMapList();
//		for (SegmentMapDescription segmentMapDescription : segmentMapList) {
//			segmentMapDescription.getSegmentOffset();
//			segmentMapDescription.getLength();
//		}
//	}

	private void determineMemoryBlocks() {
		PdbDebugInfo dbi = applicator.getPdb().getDebugInfo();
		segmentMapList = dbi.getSegmentMapList();
		if (dbi instanceof PdbNewDebugInfo) {
			DebugData debugData = ((PdbNewDebugInfo) dbi).getDebugData();
			imageSectionHeaders = debugData.getImageSectionHeadersOrig();
			if (imageSectionHeaders != null) {
				omapFromSource = debugData.getOmapFromSource();
			}
			else {
				imageSectionHeaders = debugData.getImageSectionHeaders();
			}
		}
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Filling in the maps as indicated by their descriptions.
	 * @throws PdbException If Program is null;
	 */
	private void mapPreExistingSymbols() throws PdbException {
		// Cannot do this commented-out code here... as we are relying on the primary symbol
		// map, regardless of the remap... so might need to separate the two. TODO: later thoughts
//		if (!applicator.getPdbApplicatorOptions().remapAddressUsingExistingPublicSymbols()) {
//			return;
//		}
		Program program = applicator.getProgram();
		if (program == null) {
			throw new PdbException("Program may not be null");
		}
		SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			String name = symbol.getPath().toString();
			Address address = symbol.getAddress();
			Address existingAddress = addressByPreExistingSymbolName.get(name);
			if (existingAddress == null) {
				addressByPreExistingSymbolName.put(name, address);
			}
			else if (!existingAddress.equals(address)) {
				addressByPreExistingSymbolName.put(name, Address.NO_ADDRESS);
			}
			if (primarySymbolByAddress.get(address) == null && symbol.isPrimary()) {
				primarySymbolByAddress.put(address, symbol);
			}
		}
	}

	/**
	 * Returns the address for the symbol name.  If the symbol name did not exist within the
	 * program when the list was being populated or if the name was seen at more than one address,
	 * then null is returned
	 * @param name the name of the symbol
	 * @return the address for that name or null
	 */
	private Address getAddressByPreExistingSymbolName(String name) {
		Address address = addressByPreExistingSymbolName.get(name);
		// Thin the list of map values we no longer need.  This method should only be
		// used after the list has been completely populated, and the NO_ADDRESS marker
		// was only being used during the method that populated the list to indicate that a
		// name was not unique for our needs.
		if (address != null && address.equals(Address.NO_ADDRESS)) {
			addressByPreExistingSymbolName.remove(name);
			return null;
		}
		return address;
	}

	private void createAddressRemap() {
		remapAddressByAddress = new HashMap<>();

		// Put in two basic entries so we do not have to do conditional tests before looking
		// up values in the table.
		remapAddressByAddress.put(BAD_ADDRESS, BAD_ADDRESS);
		remapAddressByAddress.put(ZERO_ADDRESS, ZERO_ADDRESS);
		remapAddressByAddress.put(EXTERNAL_ADDRESS, EXTERNAL_ADDRESS);
	}

	/**
	 * Write the mapped address for a query address, where where the mapping is
	 *  derived by using a the address of a PDB symbol as the key and finding the address of
	 *  a symbol in the program of the same "unique" name. This is accomplished using public
	 *  mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @param remapAddress the mapped address
	 */
	private void putRemapAddressByAddress(Address address, Address remapAddress) {
		Address lookup = remapAddressByAddress.get(address);
		if (lookup == null) {
			remapAddressByAddress.put(address, remapAddress);
		}
		else if (!lookup.equals(remapAddress) && lookup != BAD_ADDRESS) {
			applicator.appendLogMsg("Trying to map a mapped address to a new address... key: " +
				address + ", currentMap: " + lookup + ", newMap: " + remapAddress);
			remapAddressByAddress.put(address, BAD_ADDRESS);
		}
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Dumps memory section refinement to log.
	 * @throws CancelledException Upon user cancellation
	 */
	private void logMemorySectionRefinement() throws CancelledException {
		// Offer memory refinement (could have done it as symbols came in;  we just collected
		// them and are dealing with them now... ultimately not sure if we will want to use
		// this refinement.
		// Look at SectionFlags.java for characteristics information.
		// TODO: should we perform refinement of program memory blocks?
		PdbLog.message("\nMemorySectionRefinement");
		for (PeCoffSectionMsSymbol sym : memorySectionRefinement) {
			applicator.checkCanceled();
			String name = sym.getName();
			int section = sym.getSectionNumber();
			int relativeVirtualAddress = sym.getRva();
			int align = sym.getAlign();
			int length = sym.getLength();
			int characteristics = sym.getCharacteristics();
			Address address = imageBase.add(relativeVirtualAddress);
			PdbLog.message(String.format(
				"%s: [%04X(%08X)](%s) Align:%02X, Len:%08X, Characteristics:%08X", name, section,
				relativeVirtualAddress, address.toString(), align, length, characteristics));
		}
	}

	/**
	 * Dumps group section refinement to log.
	 * @throws CancelledException Upon user cancellation
	 */
	private void logMemoryGroupRefinement() throws CancelledException {
		// Note that I've seen example where PE header has two .data sections (one for initialized
		// and the other for uninitialized, 0x2800 and 0x250 in size, respectively), but the PDB
		// information shows two sections totally 0x2a50 size, but sizes of 0x2750 and 0x0300,
		// the latter of which is marked as ".bss" in name.  This suggests that the PE header is
		// more focused on what needs initialized, which includes 0x2750 of .data and 0xa0 of
		// .bss, the remaining 0x250 of .bss is not initialized.  These .bss portion that needs
		// initialized is lumped with the .data section in the PE header... only my opinion...
		// however, this leaves us with question of what we do here.  Do believe the PDB over
		// the PE? (See vcamp110.arm.pdb and (arm) vcamp110.dll).
		// TODO: should we perform refinement of program memory blocks?
		PdbLog.message("\nMemoryGroupRefinement");
		for (PeCoffGroupMsSymbol sym : memoryGroupRefinement) {
			applicator.checkCanceled();
			String name = sym.getName();
			int segment = sym.getSegment();
			long offset = sym.getOffset();
			int length = sym.getLength();
			int characteristics = sym.getCharacteristics();
			Address address = getAddress(sym);
			PdbLog.message(String.format("%s: [%04X:%08X](%s) Len:%08X, Characteristics:%08X", name,
				segment, offset, address.toString(), length, characteristics));
		}
	}

	//==============================================================================================
	//==============================================================================================
	// TODO: This is not complete... It was a research thought, which might get looked at in the
	// future.
	/**
	 * Tries to align section/segment information of the PDB in {@link SegmentMapDescription} from
	 * the {@link PdbDebugInfo} header substream with the memory blocks of the
	 * {@link Program}.  Initializes the lookup table to be used for processing the PDB.
	 * <P>
	 * We have seen cases where blocks of the program are combined into a single block representing
	 * one segment in the PDB.
	 * <P>
	 * The PDB's {@link SegmentMapDescription} is not always fully populated, though the length
	 * field seems to be consistently available.
	 * @throws PdbException if there was a problem processing the data.
	 */
	@SuppressWarnings("unused") // for method not being called and local variables ununsed.
	private void reconcileMemoryBlocks() throws PdbException {
//		ImageSectionHeader imageSectionHeader =
//		pdb.getDebugInfo().getDebugData().getImageSectionHeader();

		AbstractPdb pdb = applicator.getPdb();
		Program program = applicator.getProgram();
		if (program == null) {
			return;
		}

		Memory mem = program.getMemory();
		MemoryBlock[] blocks = mem.getBlocks();
		List<SegmentMapDescription> segmentMapList = pdb.getDebugInfo().getSegmentMapList();
		/**
		 * Program has additional "Headers" block set up by the {@link PeLoader}.
		 */
		int progIndexLimit = blocks.length;
		int pdbIndexLimit = segmentMapList.size();
		int progIndex = 1;
		int pdbIndex = 0;

		// Set section/segment 0 to image base. (should be what is header)

		List<SegmentInfo> myAllSegmentsInfo = new ArrayList<>(); // Contender set of segment info (vs what is in class)

		myAllSegmentsInfo.add(new SegmentInfo(blocks[0].getStart(), blocks[0].getSize()));
		// Try to match memory in order, grouping as needed.
		long blockAccum = 0;
		while (progIndex < progIndexLimit && pdbIndex < pdbIndexLimit) {
			SegmentMapDescription segmentDescription = segmentMapList.get(pdbIndex);
			Address blockStart = blocks[progIndex].getStart();
			while (blockAccum < segmentDescription.getLength() && progIndex < progIndexLimit) {
//				progIndex++;
				Address addr1 = blocks[progIndex].getStart();
				Address addr2 = blockStart.add(blockAccum);
				if (!blocks[progIndex].getStart().equals(blockStart.add(blockAccum))) {
					// Problem... blocks are not adjacent... TODO: how do we reconcile?
					throw new PdbException("Memory block reconciliation failure");
				}
				blockAccum += blocks[progIndex].getSize();
				if (blockAccum == segmentDescription.getLength()) {
					myAllSegmentsInfo.add(new SegmentInfo(blockStart, blockAccum));
					progIndex++;
					pdbIndex++;
					blockAccum = 0;
					break;
				}
				else if (blockAccum > segmentDescription.getLength()) {
					// Problem... TODO: how do we reconcile?
					throw new PdbException(
						"Memory block reconciliation failure--needs reverse aggregation");
				}
				progIndex++;
			}
		}
		if (pdbIndex == pdbIndexLimit - 1 &&
			segmentMapList.get(pdbIndex).getLength() == 0xffffffffL) {
			pdbIndex++;
		}
		if (progIndex != progIndexLimit || pdbIndex != pdbIndexLimit) {
			// Problem... TODO: didn't both end iterations together
			throw new PdbException("Memory block reconciliation failure--remaining data");
		}
	}

	//==============================================================================================
	// TODO: This is not complete... It was a research thought, which might get looked at in the
	// future.
	@SuppressWarnings("unused") // for method not being called.
	private boolean garnerSectionSegmentInformation() throws PdbException {
		AbstractPdb pdb = applicator.getPdb();
		if (pdb.getDebugInfo() == null) {
			return false;
		}

//		ImageSectionHeader imageSectionHeader =
//		pdb.getDebugInfo().getDebugData().getImageSectionHeader();

		int num = 1;
		for (AbstractModuleInformation module : pdb.getDebugInfo().getModuleInformationList()) {
			if ("* Linker *".equals(module.getModuleName())) {
				List<AbstractMsSymbol> linkerSymbolList =
					applicator.getSymbolGroupForModule(num).getSymbols();
				for (AbstractMsSymbol symbol : linkerSymbolList) {
					if (symbol instanceof PeCoffSectionMsSymbol) {
						PeCoffSectionMsSymbol section = (PeCoffSectionMsSymbol) symbol;
						int sectionNum = section.getSectionNumber();
						long realAddress = section.getRva();
						section.getLength();
						section.getCharacteristics();
						section.getAlign();
						section.getName();
						realAddressesBySection.put(sectionNum, realAddress);
					}
					if (symbol instanceof PeCoffGroupMsSymbol) {
						PeCoffGroupMsSymbol group = (PeCoffGroupMsSymbol) symbol;
						group.getName();
						group.getSegment();
						group.getLength();
						group.getOffset();
						group.getCharacteristics();
					}
				}
				return true;
			}
			num++;
		}
		return false;
	}

}
