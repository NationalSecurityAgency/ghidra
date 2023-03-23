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

import org.apache.commons.collections4.CollectionUtils;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;

/**
 * Calculates Addresses for PDB items.
 */
abstract class PdbAddressCalculator {
	private Address imageBase;
	protected List<SegmentInfo> segmentInfo = new ArrayList<>();
	private int maxSegment;

	static PdbAddressCalculator chooseAddressCalculator(PdbApplicator applicator, Address imageBase)
			throws CancelledException {

		AbstractPdb pdb = applicator.getPdb();
		PdbDebugInfo dbi = pdb.getDebugInfo();

		if (dbi instanceof PdbNewDebugInfo) {
			DebugData debugData = ((PdbNewDebugInfo) dbi).getDebugData();
			List<ImageSectionHeader> imageSectionHeaders;
			imageSectionHeaders = debugData.getImageSectionHeadersOrig();
			if (imageSectionHeaders != null) {
				SortedMap<Long, Long> omapFromSource = debugData.getOmapFromSource();
				if (omapFromSource != null) {
					return new ImageHeaderWithOmapAddressCalculator(imageBase, imageSectionHeaders,
						omapFromSource);
				}
				// Using "Orig" image section headers here (as opposed to below)
				return new ImageHeaderAddressCalculator(imageBase, imageSectionHeaders);
			}
			imageSectionHeaders = debugData.getImageSectionHeaders();
			if (imageSectionHeaders != null) {
				//Not "Orig" image section headers
				return new ImageHeaderAddressCalculator(imageBase, imageSectionHeaders);
			}
		}

		// Fall-through to here: PdbOldDebugInfo and the case of PdbNewDebugInfo where both
		// imageSectionHeaderOrig and imageSectionHeader are null.
		if (dbi != null) {
			List<SegmentMapDescription> segmentMapDescription = dbi.getSegmentMapList();
			if (segmentMapDescription != null) {
				return new SegmentMapAddressCalculator(imageBase, segmentMapDescription);
			}
		}

		List<PeCoffSectionMsSymbol> peCoffSectionSymbols =
			applicator.getLinkerPeCoffSectionSymbols();
		if (!CollectionUtils.isEmpty(peCoffSectionSymbols)) {
			//long originalImageBase = applicator.getOriginalImageBase();
			long correction = getCorrection(applicator);
			return new PeCoffSectionAddressCalculator(imageBase, correction, peCoffSectionSymbols);
		}

		Program program = applicator.getProgram();
		if (program != null) {
			MemoryBlock[] memoryBlocks = program.getMemory().getBlocks();
			if (!CollectionUtils.sizeIsEmpty(memoryBlocks)) {
				return new MemoryMapAddressCalculator(imageBase, memoryBlocks);
			}
		}

		return null;
	}

	// We wouldn't have this method if we hadn't found an example where what is supposed to be
	// an RVA in PeCoffSection is instead a VA.  Issue found in one Delphi example.  All other
	// non-Delphi examples seem to have RVA.
	static long getCorrection(PdbApplicator applicator) throws CancelledException {

		AbstractMsSymbol symbol = applicator.getLinkerModuleCompileSymbol();
		String name = "";
		if (symbol instanceof Compile3MsSymbol) {
			Compile3MsSymbol compile3MsSymbol = (Compile3MsSymbol) symbol;
			name = compile3MsSymbol.getCompilerVersionString();
		}
		else if (symbol instanceof AbstractCompile2MsSymbol) {
			AbstractCompile2MsSymbol compile2MsSymbol = (AbstractCompile2MsSymbol) symbol;
			name = compile2MsSymbol.getCompilerVersionString();
		}

		// Note, that we can also check version numbers if different versions of map2pdb (in the
		// compile symbol).
		if ("map2pdb".equals(name)) {
			return applicator.getOriginalImageBase();
		}
		return 0L;

		// We considered going the route of checking the program for Delphi tool chain, but instead
		// went the route above in checking where the COFF symbols came from and that the fact
		// that we've seen them contain Virtual Address instead of Relative Virtual Address could
		// instead be due to map2pdb instead of the Delphi compiler.  We just don't know at this
		// time.  This deserved more investigation with more data.
//		CompilerSpec spec = applicator.getProgram().getCompilerSpec();
//		String compiler = applicator.getProgram().getCompiler();
//		if ("borland::pascal".equals(compiler)) {
//		}
//		CompilerSpecDescription desc = spec.getCompilerSpecDescription();
//		String specName = desc.getCompilerSpecName();
//		if ("Delphi".equals(specName)) {
//		}
//		CompilerSpecID id = desc.getCompilerSpecID();
	}

	//==============================================================================================
	PdbAddressCalculator(Address imageBase, List<SegmentInfo> segmentInfo) {
		this.segmentInfo = segmentInfo;
		this.imageBase = imageBase;
		maxSegment = segmentInfo.size() + 1;
	}

	Address getAddress(int segment, long offset) {
		if (segment > maxSegment) {
			return PdbAddressManager.BAD_ADDRESS;
		}
		else if (segment == 0 || segment == maxSegment) {
			// External address.
			return PdbAddressManager.EXTERNAL_ADDRESS;
		}
		Long rva = getRva(segment, offset);
		if (rva == null) {
			return PdbAddressManager.BAD_ADDRESS;
		}
		if (rva == 0) {
			return PdbAddressManager.ZERO_ADDRESS;
		}
		return imageBase.add(rva);
	}

	protected Long getRva(int segment, long offset) {
		return segmentInfo.get(segment - 1).getStart() + offset;
	}

	/**
	 * Clean up possibly incomplete segment information, by synthesizing missing offset data.
	 * @param segments segments to correct
	 * @param firstSectionOffset "known" first section offset
	 * @param imageAlign section alignment
	 * @return new synthesized segment info with synthesized offsets
	 */
	protected static List<SegmentInfo> synthesizeSegmentInfo(List<SegmentInfo> segments,
			long firstSectionOffset, long imageAlign) {

		long mask = -imageAlign;
		long addend = imageAlign - 1;

		long determinedSectionOffset = firstSectionOffset;
		long origSectionOffset;
		long sectionLength = 0; // setting "previous" section length to zero for first pass.

		List<SegmentInfo> synthesizedSegmentInfo = new ArrayList<>();
		for (SegmentInfo info : segments) {
			origSectionOffset = info.getStart();
			if (origSectionOffset != 0x00L) {
				determinedSectionOffset = origSectionOffset;
			}
			else {
				// Performing "least integer" (ceiling) function with imageAlign:
				// resultAlign = (long)(imageAlign * leastInteger((double) val / (double) imageAlign))
				// where imageAlign must be a non-zero power of two for this calculation.
				// Uses previous section length.
				determinedSectionOffset += (sectionLength + addend) & mask;
			}

			// the current section length is used for next section offset calculation.
			sectionLength = info.getLength();
			SegmentInfo synthesized = new SegmentInfo(determinedSectionOffset, sectionLength);
			synthesizedSegmentInfo.add(synthesized);
		}

		return synthesizedSegmentInfo;
	}

	//----------------------------------------------------------------------------------------------
	static class ImageHeaderAddressCalculator extends PdbAddressCalculator {
		ImageHeaderAddressCalculator(Address imageBase,
				List<ImageSectionHeader> imageSectionHeaders) {
			super(imageBase, init(imageBase, imageSectionHeaders));
		}

		static List<SegmentInfo> init(Address imageBase,
				List<ImageSectionHeader> imageSectionHeaders) {
			List<SegmentInfo> segments = new ArrayList<>();
			for (ImageSectionHeader imageSectionHeader : imageSectionHeaders) {
				SegmentInfo segment = new SegmentInfo(imageSectionHeader.getVirtualAddress(),
					imageSectionHeader.getRawDataSize());
				segments.add(segment);
			}
			return segments;
		}
	}

	static class ImageHeaderWithOmapAddressCalculator extends PdbAddressCalculator {
		private SortedMap<Long, Long> omapFromSource;

		ImageHeaderWithOmapAddressCalculator(Address imageBase,
				List<ImageSectionHeader> imageSectionHeaders,
				SortedMap<Long, Long> omapFromSource) {
			super(imageBase, ImageHeaderAddressCalculator.init(imageBase, imageSectionHeaders));
			this.omapFromSource = omapFromSource;
		}

		@Override
		protected Long getRva(int segment, long offset) {
			return applyOMap(super.getRva(segment, offset));
		}

		private Long applyOMap(Long relativeVirtualAddress) {
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

	}

	static class SegmentMapAddressCalculator extends PdbAddressCalculator {
		SegmentMapAddressCalculator(Address imageBase,
				List<SegmentMapDescription> segmentMapDescriptions) {
			super(imageBase, init(imageBase, segmentMapDescriptions));
		}

		private static List<SegmentInfo> init(Address imageBase,
				List<SegmentMapDescription> segmentMapDescriptions) {
			List<SegmentInfo> segments = new ArrayList<>();

			for (SegmentMapDescription smd : segmentMapDescriptions) {
				SegmentInfo segment = new SegmentInfo(smd.getOffset(), smd.getLength());
				segments.add(segment);
			}
			// Currently, this is the only calculator using synthesis to correct offset.
			// If all used it, we would put this in the parent class constructor.
			//
			// We have the defaults for offset of initial segment and for segment align size to both
			// be 0x1000.  If we determine that these need to be different for the various data
			//  sources, then the AddressCalculator constructor can take these values as parameters
			// and pass them to the following synthesize method.
			return synthesizeSegmentInfo(segments, 0x1000L, 0x1000L);
		}

	}

	static class PeCoffSectionAddressCalculator extends PdbAddressCalculator {
		PeCoffSectionAddressCalculator(Address imageBase, long correction,
				List<PeCoffSectionMsSymbol> peCoffSectionSymbols) {
			super(imageBase, init(imageBase, correction, peCoffSectionSymbols));
		}

		private static List<SegmentInfo> init(Address imageBase, long correction,
				List<PeCoffSectionMsSymbol> peCoffSectionSymbols) {
			List<SegmentInfo> segments = new ArrayList<>();

			// One last check to see if we should apply the correction.  If the original image
			// base is greater than any of the addresses here, then the addresses cannot be
			// Virtual Addresses, but instead Relative Virtual Addresses.  So set correction back
			// to zero (if not already zero).
			for (PeCoffSectionMsSymbol symbol : peCoffSectionSymbols) {
				long rva = symbol.getRva();
				if (rva != 0 && rva < correction) {
					correction = 0L;
					break;
				}
			}

			for (PeCoffSectionMsSymbol symbol : peCoffSectionSymbols) {
				int offset = symbol.getRva();
				if (offset != 0) {
					offset -= correction;
				}
				SegmentInfo segment = new SegmentInfo(offset, symbol.getLength());
				segments.add(segment);
			}
			return segments;
		}
	}

	static class MemoryMapAddressCalculator extends PdbAddressCalculator {
		MemoryMapAddressCalculator(Address imageBase, MemoryBlock[] memoryBlocks) {
			super(imageBase, init(imageBase, memoryBlocks));
		}

		private static List<SegmentInfo> init(Address imageBase, MemoryBlock[] blocks) {
			List<SegmentInfo> segments = new ArrayList<>();
			for (MemoryBlock block : blocks) {
				long offset = block.getStart().subtract(imageBase);
				SegmentInfo segment = new SegmentInfo(offset, block.getSize());
				segments.add(segment);
			}
			return segments;
		}
	}

	//==============================================================================================
	private static class SegmentInfo {
		private long start;
		private long length;

		SegmentInfo(long startIn, long lengthIn) {
			start = startIn;
			length = lengthIn;
		}

		public long getStart() {
			return start;
		}

		public long getLength() {
			return length;
		}

		@Override
		public String toString() {
			return String.format("start: %08x length: %08x", start, length);
		}
	}

}
