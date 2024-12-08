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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.NList;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.file.formats.ios.ExtractedMacho;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * A class for extracting components from a {@link DyldCacheFileSystem}
 */
public class DyldCacheExtractor {

	/**
	 * A footer that gets appended to the end of every extracted component so Ghidra can identify
	 * them and treat them special when imported
	 */
	public static final byte[] FOOTER_V1 =
		"Ghidra DYLD extraction v1".getBytes(StandardCharsets.US_ASCII);

	/**
	 * A {@link DyldCacheMappingAndSlideInfo} with a possibly reduced set of available addresses
	 * within the mapping
	 * 
	 * @param mappingInfo A {@link DyldCacheMappingAndSlideInfo}
	 * @param rangeSet A a possibly reduced set of available addresses within the mapping
	 */
	public record MappingRange(DyldCacheMappingAndSlideInfo mappingInfo, RangeSet<Long> rangeSet) {}

	/**
	 * Gets a {@link ByteProvider} that contains a DYLIB from a {@link DyldCacheFileSystem}.  The
	 * DYLIB's header will be altered to account for its segment bytes being packed down.   
	 * 
	 * @param dylibOffset The offset of the DYLIB in the given provider
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param index The DYLIB's {@link SplitDyldCache} index
	 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the DYLIB
	 * @throws MachException If there was an error parsing the DYLIB headers
	 * @throws IOException If there was an IO-related issue with extracting the DYLIB
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static ByteProvider extractDylib(long dylibOffset, SplitDyldCache splitDyldCache,
			int index, Map<DyldCacheSlideInfoCommon, List<DyldFixup>> slideFixupMap,
			FSRL fsrl, TaskMonitor monitor) throws IOException, MachException, CancelledException {

		ExtractedMacho extractedMacho = new DyldPackedSegments(dylibOffset, splitDyldCache, index,
			FOOTER_V1, slideFixupMap, monitor);
		extractedMacho.pack();
		return extractedMacho.getByteProvider(fsrl);
	}

	/**
	 * Gets a {@link ByteProvider} that contains a byte mapping from a {@link DyldCacheFileSystem}
	 * 
	 * @param mappingRange The {@link MappingRange}
	 * @param segmentName The name of the segment in the resulting Mach-O
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param index The mapping's {@link SplitDyldCache} index
	 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the mapping
	 * @throws MachException If there was an error creating Mach-O headers
	 * @throws IOException If there was an IO-related issue with extracting the mapping
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static ByteProvider extractMapping(MappingRange mappingRange, String segmentName,
			SplitDyldCache splitDyldCache, int index,
			Map<DyldCacheSlideInfoCommon, List<DyldFixup>> slideFixupMap, FSRL fsrl,
			TaskMonitor monitor) throws IOException, MachException, CancelledException {

		int magic = MachConstants.MH_MAGIC_64;
		List<Range<Long>> ranges = new ArrayList<>(mappingRange.rangeSet().asRanges());
		DyldCacheMappingAndSlideInfo mappingInfo = mappingRange.mappingInfo();
		int allSegmentsSize = SegmentCommand.size(magic) * ranges.size();

		// Fix slide pointers
		ByteProvider origProvider = splitDyldCache.getProvider(index);
		byte[] fixedProviderBytes = origProvider.readBytes(0, origProvider.length());
		DyldCacheSlideInfoCommon slideInfo = slideFixupMap.keySet()
				.stream()
				.filter(e -> e.getMappingAddress() == mappingInfo.getAddress())
				.findFirst()
				.orElse(null);
		if (slideInfo != null) {
			List<DyldFixup> slideFixups = slideFixupMap.get(slideInfo);
			monitor.initialize(slideFixups.size(), "Fixing slide pointers...");
			for (DyldFixup fixup : slideFixups) {
				monitor.increment();
				long fileOffset = slideInfo.getMappingFileOffset() + fixup.offset();
				byte[] newBytes = ExtractedMacho.toBytes(fixup.value(), fixup.size());
				System.arraycopy(newBytes, 0, fixedProviderBytes, (int) fileOffset,
					newBytes.length);
			}
		}

		// Mach-O Header
		byte[] header = MachHeader.create(magic, 0x100000c, 0x80000002, 6, ranges.size(),
			allSegmentsSize, 0x42100085, 0);

		// Segment commands and data
		List<byte[]> segments = new ArrayList<>();
		List<byte[]> data = new ArrayList<>();
		int current = header.length + allSegmentsSize;
		try (ByteProvider fixedProvider = new ByteArrayProvider(fixedProviderBytes)) {
			for (int i = 0; i < ranges.size(); i++) {
				Range<Long> range = ranges.get(i);

				// Segment Command
				long dataSize = range.upperEndpoint() - range.lowerEndpoint();
				segments.add(
					SegmentCommand.create(magic, "%s.%d.%d".formatted(segmentName, index, i),
						range.lowerEndpoint(), dataSize, current, dataSize,
						mappingInfo.getMaxProtection(), mappingInfo.getMaxProtection(), 0, 0));

				// Data
				data.add(fixedProvider.readBytes(
					range.lowerEndpoint() - mappingInfo.getAddress() + mappingInfo.getFileOffset(),
					dataSize));

				current += dataSize;
			}
		}

		// Combine pieces
		int dataSize = data.stream().mapToInt(d -> d.length).sum();
		int totalSize = header.length + allSegmentsSize + dataSize;
		byte[] result = new byte[totalSize + FOOTER_V1.length];
		System.arraycopy(header, 0, result, 0, header.length);
		current = header.length;
		for (byte[] segment : segments) {
			System.arraycopy(segment, 0, result, current, segment.length);
			current += segment.length;
		}
		for (byte[] d : data) {
			System.arraycopy(d, 0, result, current, d.length);
			current += d.length;
		}

		// Add footer
		System.arraycopy(FOOTER_V1, 0, result, result.length - FOOTER_V1.length, FOOTER_V1.length);

		return new ByteArrayProvider(result, fsrl);
	}

	/**
	 * Gets a {@link Map} of {DyldCacheSlideInfoCommon}s to their corresponding {@link DyldFixup}s
	 * 
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param monitor {@link TaskMonitor}
	 * @return A {@link Map} of {DyldCacheSlideInfoCommon}s to their corresponding 
	 *   {@link DyldFixup}s
	 * @throws CancelledException If the user cancelled the operation
	 * @throws IOException If there was an IO-related issue with getting the slide fixups
	 */
	public static Map<DyldCacheSlideInfoCommon, List<DyldFixup>> getSlideFixups(
			SplitDyldCache splitDyldCache, TaskMonitor monitor)
			throws CancelledException, IOException {
		Map<DyldCacheSlideInfoCommon, List<DyldFixup>> slideFixupMap = new HashMap<>();
		MessageLog log = new MessageLog();

		for (int i = 0; i < splitDyldCache.size(); i++) {
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			ByteProvider bp = splitDyldCache.getProvider(i);
			DyldArchitecture arch = header.getArchitecture();
			for (DyldCacheSlideInfoCommon slideInfo : header.getSlideInfos()) {
				try (ByteProvider wrapper = new ByteProviderWrapper(bp,
					slideInfo.getMappingFileOffset(), slideInfo.getMappingSize())) {
					BinaryReader wrapperReader =
						new BinaryReader(wrapper, !arch.getEndianness().isBigEndian());
					List<DyldFixup> fixups = slideInfo.getSlideFixups(wrapperReader,
						arch.is64bit() ? 8 : 4, log, monitor);
					slideFixupMap.put(slideInfo, fixups);
				}
			}
		}

		return slideFixupMap;
	}

	/**
	 * A packed DYLIB that was once living inside of a DYLD shared cache.  The DYLIB is said to be 
	 * packed because its segment file bytes, which were not adjacent in its containing DYLD, are 
	 * now adjacent in its new array. 
	 */
	private static class DyldPackedSegments extends ExtractedMacho {

		private SplitDyldCache splitDyldCache;
		private Map<DyldCacheSlideInfoCommon, List<DyldFixup>> slideFixupMap;

		/**
		 * Creates a new {@link DyldPackedSegments} object
		 * 
		 * @param dylibOffset The offset of the DYLIB in the given provider
		 * @param splitDyldCache The {@link SplitDyldCache}
		 * @param index The DYLIB's {@link SplitDyldCache} index
		 * @param footer A footer that gets appended to the end of every extracted component so 
		 *   Ghidra can identify them and treat them special when imported
		 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
		 * @param monitor {@link TaskMonitor}
		 * @throws MachException If there was an error parsing the DYLIB headers
		 * @throws IOException If there was an IO-related error
		 * @throws CancelledException If the user cancelled the operation
		 */
		public DyldPackedSegments(long dylibOffset, SplitDyldCache splitDyldCache, int index,
				byte[] footer, Map<DyldCacheSlideInfoCommon, List<DyldFixup>> slideFixupMap,
				TaskMonitor monitor) throws MachException, IOException, CancelledException {
			super(splitDyldCache.getProvider(index), dylibOffset,
				new MachHeader(splitDyldCache.getProvider(index), dylibOffset, false)
						.parse(splitDyldCache),
				footer, monitor);
			this.splitDyldCache = splitDyldCache;
			this.slideFixupMap = slideFixupMap;
		}

		@Override
		public void pack() throws IOException, CancelledException {
			super.pack();
			fixupSlidePointers();
		}

		@Override
		protected ByteProvider getSegmentProvider(SegmentCommand segment) throws IOException {
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader dyldCacheheader = splitDyldCache.getDyldCacheHeader(i);
				for (DyldCacheMappingInfo mappingInfo : dyldCacheheader.getMappingInfos()) {
					if (mappingInfo.contains(segment.getVMaddress())) {
						return splitDyldCache.getProvider(i);
					}
				}
			}
			throw new IOException(
				"Failed to find provider for segment: " + segment.getSegmentName());
		}

		@Override
		protected List<NList> getExtraSymbols() {
			long base = splitDyldCache.getBaseAddress();
			DyldCacheLocalSymbolsInfo info = splitDyldCache.getLocalSymbolInfo();
			return info != null ? info.getNList(textSegment.getVMaddress() - base) : List.of();
		}

		/**
		 * Fixes-up the slide pointers
		 * 
		 * @throws IOException If there was an IO-related issue performing the fix-up
		 * @throws CancelledException If the user cancelled the operation
		 */
		private void fixupSlidePointers() throws IOException, CancelledException {
			// TODO; Optimize this fixup algorithm
			long total = slideFixupMap.values().stream().flatMap(List::stream).count();
			monitor.initialize(total, "Fixing slide pointers...");
			for (DyldCacheSlideInfoCommon slideInfo : slideFixupMap.keySet()) {
				for (DyldFixup fixup : slideFixupMap.get(slideInfo)) {
					monitor.increment();
					long addr = slideInfo.getMappingAddress() + fixup.offset();
					long fileOffset = slideInfo.getMappingFileOffset() + fixup.offset();
					SegmentCommand segment = getSegmentContaining(addr);
					if (segment == null) {
						// Fixup is not in this Mach-O
						continue;
					}
					byte[] newBytes = ExtractedMacho.toBytes(fixup.value(), fixup.size());
					try {
						System.arraycopy(newBytes, 0, packed,
							(int) getPackedOffset(fileOffset, segment), newBytes.length);
					}
					catch (NotFoundException e) {
						throw new IOException(e);
					}
				}
			}
		}

		/**
		 * Gets the {@link SegmentCommand segment} that contains the given virtual address
		 * 
		 * @param addr The address
		 * @return The {@link SegmentCommand segment} that contains the given virtual address
		 */
		private SegmentCommand getSegmentContaining(long addr) {
			for (SegmentCommand segment : machoHeader.getAllSegments()) {
				if (addr >= segment.getVMaddress() &&
					addr < segment.getVMaddress() + segment.getVMsize()) {
					return segment;
				}
			}
			return null;
		}
	}
}

