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
	 * Gets a {@link ByteProvider} that contains a DYLIB from a {@link DyldCacheFileSystem}.  The
	 * DYLIB's header will be altered to account for its segment bytes being packed down.   
	 * 
	 * @param entry The mapping's {@link DyldCacheEntry}
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the DYLIB
	 * @throws MachException If there was an error parsing the DYLIB headers
	 * @throws IOException If there was an IO-related issue with extracting the DYLIB
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static ByteProvider extractDylib(DyldCacheEntry entry, SplitDyldCache splitDyldCache,
			Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap, FSRL fsrl,
			TaskMonitor monitor) throws IOException, MachException, CancelledException {
		long dylibOffset = entry.rangeSet().asRanges().iterator().next().lowerEndpoint() -
			splitDyldCache.getDyldCacheHeader(entry.splitCacheIndex()).getBaseAddress();
		ExtractedMacho extractedMacho = new DyldPackedSegments(dylibOffset, splitDyldCache,
			entry.splitCacheIndex(), FOOTER_V1, slideFixupMap, monitor);
		extractedMacho.pack();
		return extractedMacho.getByteProvider(fsrl);
	}

	/**
	 * Gets a {@link ByteProvider} that contains a byte mapping from a {@link DyldCacheFileSystem}
	 * 
	 * @param entry The mapping's {@link DyldCacheEntry}
	 * @param segmentName The name of the segment in the resulting Mach-O
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the mapping
	 * @throws MachException If there was an error creating Mach-O headers
	 * @throws IOException If there was an IO-related issue with extracting the mapping
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static ByteProvider extractMapping(DyldCacheEntry entry, String segmentName,
			SplitDyldCache splitDyldCache,
			Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap, FSRL fsrl,
			TaskMonitor monitor) throws IOException, MachException, CancelledException {

		int magic = MachConstants.MH_MAGIC_64;
		List<Range<Long>> ranges = new ArrayList<>(entry.rangeSet().asRanges());
		DyldCacheMappingInfo mappingInfo = entry.mappingInfo();
		int allSegmentsSize = SegmentCommand.size(magic) * ranges.size();

		// Mach-O Header
		byte[] header = MachHeader.create(magic, 0x100000c, 0x80000002, 6, ranges.size(),
			allSegmentsSize, 0x42100085, 0);

		// Segment commands and data
		List<byte[]> segments = new ArrayList<>();
		List<byte[]> data = new ArrayList<>();
		int current = header.length + allSegmentsSize;
		try (ByteProvider slidProvider =
			new DyldCacheSlidProvider(entry.mappingInfo(), splitDyldCache, entry.splitCacheIndex(),
				slideFixupMap, monitor)) {
			for (int i = 0; i < ranges.size(); i++) {
				Range<Long> range = ranges.get(i);

				// Segment Command
				long dataSize = range.upperEndpoint() - range.lowerEndpoint();
				segments.add(
					SegmentCommand.create(magic,
						"%s.%d.%d".formatted(segmentName, entry.splitCacheIndex(), i),
						range.lowerEndpoint(), dataSize, current, dataSize,
						mappingInfo.getMaxProtection(), mappingInfo.getMaxProtection(), 0));

				// Data
				data.add(slidProvider.readBytes(
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
	public static Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> getSlideFixups(
			SplitDyldCache splitDyldCache, TaskMonitor monitor)
			throws CancelledException, IOException {
		Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap = new HashMap<>();
		MessageLog log = new MessageLog();

		for (int i = 0; i < splitDyldCache.size(); i++) {
			DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
			ByteProvider bp = splitDyldCache.getProvider(i);
			DyldArchitecture arch = header.getArchitecture();
			for (DyldCacheSlideInfoCommon slideInfo : header.getSlideInfos()) {
				DyldCacheMappingInfo mappingInfo = slideInfo.getMappingInfo();
				try (ByteProvider wrapper = new ByteProviderWrapper(bp, mappingInfo.getFileOffset(),
					mappingInfo.getSize())) {
					BinaryReader wrapperReader =
						new BinaryReader(wrapper, !arch.getEndianness().isBigEndian());
					List<DyldFixup> fixups = slideInfo.getSlideFixups(wrapperReader,
						arch.is64bit() ? 8 : 4, log, monitor);
					HashMap<Long, DyldFixup> subMap = new HashMap<>();
					for (DyldFixup fixup : fixups) {
						subMap.put(mappingInfo.getFileOffset() + fixup.offset(), fixup);
					}
					slideFixupMap.put(mappingInfo, subMap);
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
		private Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap;

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
				byte[] footer, Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap,
				TaskMonitor monitor) throws MachException, IOException, CancelledException {
			super(splitDyldCache.getProvider(index), dylibOffset,
				new MachHeader(splitDyldCache.getProvider(index), dylibOffset, false)
						.parse(splitDyldCache),
				footer, monitor);
			this.splitDyldCache = splitDyldCache;
			this.slideFixupMap = slideFixupMap;
		}

		@Override
		protected ByteProvider getSegmentProvider(SegmentCommand segment) throws IOException {
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader dyldCacheheader = splitDyldCache.getDyldCacheHeader(i);
				for (DyldCacheMappingInfo mappingInfo : dyldCacheheader.getMappingInfos()) {
					if (mappingInfo.contains(segment.getVMaddress(), true)) {
						return new DyldCacheSlidProvider(mappingInfo, splitDyldCache, i,
							slideFixupMap, monitor);
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
	}
}

