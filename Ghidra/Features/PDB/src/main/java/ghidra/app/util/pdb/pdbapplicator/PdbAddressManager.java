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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

/**
 * Manages Address/Section/Segment-related PDB items.
 *  Has method for providing real addresses.
 */
public class PdbAddressManager {

	private static final Address badAddress = Address.NO_ADDRESS; // using NO_ADDRESS as a marker

	//==============================================================================================
	private Map<Integer, Long> realAddressesBySection;
	private List<PeCoffGroupMsSymbol> memoryGroupRefinement;
	private List<PeCoffSectionMsSymbol> memorySectionRefinement;
	private List<SegmentInfo> allSegmentsInfo;
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
		allSegmentsInfo = new ArrayList<>();
		remapAddressByAddress = new HashMap<>();

		determineMemoryBlocks();
	}

	/**
	 * Returns the Address for the given section and offset.
	 * @param symbol The {@link AddressMsSymbol}
	 * @return The Address
	 */
	// Returns an address using the section and offset.
	Address reladdr(AddressMsSymbol symbol) {
		return reladdr(symbol.getSegment(), symbol.getOffset());
	}

	/**
	 * Returns the Address for the given section and offset.  Will attempt to map the address
	 *  to a new address if the {@link PdbApplicatorOptions}
	 * @param segment The segment
	 * @param offset The offset
	 * @return The Address, which can be {@code Address.NO_ADDRESS} if it was the original address.
	 */
	// Returns an address using the section and offset.
	Address reladdr(int segment, long offset) {
		if (segment < 0 || segment > allSegmentsInfo.size()) {
			return Address.NO_ADDRESS;
		}
		else if (segment == allSegmentsInfo.size()) {
			// Was getting issues of _IMAGE_DOSHEADER showing up with a segemnt index one
			//  beyond the end.
			segment = 0; // The anomaly of last segment meaning the first.
		}
		SegmentInfo segmentInfo = allSegmentsInfo.get(segment);
		if (offset >= segmentInfo.getLength()) {
			return Address.NO_ADDRESS;
		}
		return segmentInfo.getStartAddress().add(offset);
	}

	/**
	 * Write the mapped address for a query address, where where the mapping is
	 *  derived by using a the address of a PDB symbol as the key and finding the address of
	 *  a symbol in the program of the same "unique" name. This is accomplished using public
	 *  mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @param remapAddress the mapped address
	 */
	void putRemapAddressByAddress(Address address, Address remapAddress) {
		Address lookup = remapAddressByAddress.get(address);
		if (lookup == null) {
			remapAddressByAddress.put(address, remapAddress);
		}
		else if (!lookup.equals(remapAddress) && lookup != badAddress) {
			applicator.appendLogMsg("Trying to map a mapped address to a new address... key: " +
				address + ", currentMap: " + lookup + ", newMap: " + remapAddress);
			remapAddressByAddress.put(address, badAddress);
		}
	}

	/**
	 * Returns the Address of an existing symbol for the query address, where the mapping is
	 *  derived by using a the address of a PDB symbol as the key and finding the address of
	 *  a symbol in the program of the same "unique" name. This is accomplished using public
	 *  mangled symbols.  If the program symbol came from the PDB, then it maps to itself.
	 * @param address the query address
	 * @return the remapAddress
	 */
	Address getRemapAddressByAddress(Address address) {
		if (!Address.NO_ADDRESS.equals(address) &&
			applicator.getPdbApplicatorOptions().remapAddressUsingExistingPublicMangledSymbols()) {
			return remapAddressByAddress.getOrDefault(address, address);
		}
		return address;
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

	private void determineMemoryBlocks() {
		// Set section/segment 0 to image base. (should be what is header), but what is its size?
		//  TODO... made up size for now... is there something else?  We could 
		long segmentZeroLength = 0x7fffffff;
		allSegmentsInfo.add(new SegmentInfo(imageBase, segmentZeroLength));
		AbstractDatabaseInterface dbi = applicator.getPdb().getDatabaseInterface();
		if (dbi instanceof DatabaseInterfaceNew) {
			DebugData debugData = ((DatabaseInterfaceNew) dbi).getDebugData();
			List<ImageSectionHeader> imageSectionHeaders = debugData.getImageSectionHeaders();
			for (ImageSectionHeader imageSectionHeader : imageSectionHeaders) {
				long virtualAddress = imageSectionHeader.getVirtualAddress();
				// TODO: not sure when unionPAVS is physical address vs. virtual size.  Perhaps
				//  it keys off whether virtualAddress is not some special value such as
				//  0x00000000 or 0xffffffff.
				long size = imageSectionHeader.getUnionPAVS();
				allSegmentsInfo.add(new SegmentInfo(imageBase.add(virtualAddress), size));
			}
		}
		// else instance of DatabaseInterface; TODO: what can we do here?

		// TODO: what should we do with these? Not doing anything at the moment
		AbstractPdb pdb = applicator.getPdb();
		List<SegmentMapDescription> segmentMapList = pdb.getDatabaseInterface().getSegmentMapList();
		for (SegmentMapDescription segmentMapDescription : segmentMapList) {
			segmentMapDescription.getSegmentOffset();
			segmentMapDescription.getLength();
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
		//  them and are dealing with them now... ultimately not sure if we will want to use
		//  this refinement.
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
		//  and the other for uninitialized, 0x2800 and 0x250 in size, respectively), but the PDB
		//  information shows two sections totally 0x2a50 size, but sizes of 0x2750 and 0x0300,
		//  the latter of which is marked as ".bss" in name.  This suggests that the PE header is
		//  more focused on what needs initialized, which includes 0x2750 of .data and 0xa0 of
		//  .bss, the remaining 0x250 of .bss is not initialized.  These .bss portion that needs
		//  initialized is lumped with the .data section in the PE header... only my opinion...
		//  however, this leaves us with question of what we do here.  Do believe the PDB over
		//  the PE? (See vcamp110.arm.pdb and (arm) vcamp110.dll).
		// TODO: should we perform refinement of program memory blocks?
		PdbLog.message("\nMemoryGroupRefinement");
		for (PeCoffGroupMsSymbol sym : memoryGroupRefinement) {
			applicator.checkCanceled();
			String name = sym.getName();
			int segment = sym.getSegment();
			long offset = sym.getOffset();
			int length = sym.getLength();
			int characteristics = sym.getCharacteristics();
			Address address = reladdr(sym);
			PdbLog.message(String.format("%s: [%04X:%08X](%s) Len:%08X, Characteristics:%08X", name,
				segment, offset, address.toString(), length, characteristics));
		}
	}

	//==============================================================================================
	//==============================================================================================
	// TODO: This is not complete... It was a research thought, which might get looked at in the
	//  future.
	/**
	 * Tries to align section/segment information of the PDB in {@link SegmentMapDescription} from
	 * the {@link AbstractDatabaseInterface} header substream with the memory blocks of the
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
//		pdb.getDatabaseInterface().getDebugData().getImageSectionHeader();

		AbstractPdb pdb = applicator.getPdb();
		Program program = applicator.getProgram();
		if (program == null) {
			return;
		}

		Memory mem = program.getMemory();
		MemoryBlock[] blocks = mem.getBlocks();
		List<SegmentMapDescription> segmentMapList = pdb.getDatabaseInterface().getSegmentMapList();
		/**
		 *  Program has additional "Headers" block set up by the {@link PeLoader}.
		 */
		int progIndexLimit = blocks.length;
		int pdbIndexLimit = segmentMapList.size();
		int progIndex = 1;
		int pdbIndex = 0;

		// Set section/segment 0 to image base. (should be what is header)

		List<SegmentInfo> myAllSegmentsInfo = new ArrayList<>(); // Contender set of segment info (vs what is in class)

		allSegmentsInfo.add(new SegmentInfo(blocks[0].getStart(), blocks[0].getSize()));
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
	//  future.
	@SuppressWarnings("unused") // for method not being called.
	private boolean garnerSectionSegmentInformation() throws PdbException {
		AbstractPdb pdb = applicator.getPdb();
		if (pdb.getDatabaseInterface() == null) {
			return false;
		}

//		ImageSectionHeader imageSectionHeader =
//		pdb.getDatabaseInterface().getDebugData().getImageSectionHeader();

		int num = 1;
		for (AbstractModuleInformation module : pdb.getDatabaseInterface().getModuleInformationList()) {
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
