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

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Utilities methods for working with Mach-O DYLD shared cache binaries.
 */
public class DyldCacheUtils {

	/**
	 * Determines if the given {@link Program} is a DYLD cache.
	 * 
	 * @param program The {@link Program}
	 * @return True if the given {@link Program} is a DYLD cache; otherwise, false
	 */
	public final static boolean isDyldCache(Program program) {
		if (program == null) {
			return false;
		}
		if (program.getMemory().getSize() < DyldArchitecture.DYLD_V1_SIGNATURE_LEN) {
			return false;
		}
		byte[] bytes = new byte[DyldArchitecture.DYLD_V1_SIGNATURE_LEN];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return isDyldCache(new String(bytes).trim());
	}

	/**
	 * Determines if the given {@link ByteProvider} is a DYLD cache.
	 * 
	 * @param provider The {@link ByteProvider}
	 * @return True if the given {@link ByteProvider} is a DYLD cache; otherwise, false
	 */
	public final static boolean isDyldCache(ByteProvider provider) {
		if (provider == null) {
			return false;
		}
		byte[] bytes = new byte[DyldArchitecture.DYLD_V1_SIGNATURE_LEN];
		try {
			bytes = provider.readBytes(0, DyldArchitecture.DYLD_V1_SIGNATURE_LEN);
		}
		catch (IOException e) {
			return false;
		}
		return isDyldCache(new String(bytes).trim());
	}

	/**
	 * A {@link DyldCacheImage} and its corresponding metadata
	 * 
	 * @param image The {@link DyldCacheImage}
	 * @param splitCacheIndex The image's index in the {@link SplitDyldCache}
	 */
	public record DyldCacheImageRecord(DyldCacheImage image, int splitCacheIndex) {}

	/**
	 * Gets all the {@link DyldCacheImageRecord}s for the given {@link List} of 
	 * {@link DyldCacheHeader}s
	 * 
	 * @param headers The {@link List} of {@link DyldCacheHeader}s
	 * @return A {@link List} of {@link DyldCacheImageRecord}s
	 */
	public final static List<DyldCacheImageRecord> getImageRecords(List<DyldCacheHeader> headers) {
		Set<Long> addrs = new HashSet<>();
		List<DyldCacheImageRecord> imageRecords = new ArrayList<>();
		for (DyldCacheHeader header : headers) {
			for (DyldCacheImage image : header.getImageInfos()) {
				if (addrs.contains(image.getAddress())) {
					continue;
				}
				for (int i = 0; i < headers.size(); i++) {
					for (DyldCacheMappingInfo mappingInfo : headers.get(i).getMappingInfos()) {
						if (mappingInfo.contains(image.getAddress(), true)) {
							imageRecords.add(new DyldCacheImageRecord(image, i));
							addrs.add(image.getAddress());
							break;
						}
					}
				}
			}
		}
		return imageRecords;
	}

	/**
	 * Determines if the given signature represents a DYLD cache signature with an architecture we
	 * support.
	 * 
	 * @param signature The DYLD cache signature
	 * @return True if the given signature represents a DYLD cache signature with an architecture we
	 * support; otherwise, false
	 */
	public final static boolean isDyldCache(String signature) {
		for (DyldArchitecture architecture : DyldArchitecture.ARCHITECTURES) {
			if (architecture.getSignature().equals(signature)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Class to store a "split" DYLD Cache, which is split across several subcache files (base file,
	 * .1, .2, .symbols, etc).
	 */
	public static class SplitDyldCache implements Closeable {

		private List<ByteProvider> providers = new ArrayList<>();
		private List<DyldCacheHeader> headers = new ArrayList<>();
		private List<String> names = new ArrayList<>();
		private FileSystemService fsService = FileSystemService.getInstance();

		/**
		 * Creates a new {@link SplitDyldCache}
		 * 
		 * @param baseProvider The {@link ByteProvider} of the "base" DYLD Cache file
		 * @param shouldProcessLocalSymbols True if local symbols should be processed; otherwise, 
		 *   false
		 * @param log The log
		 * @param monitor A cancelable task monitor
		 * @throws IOException If there was an IO-related issue with processing the split DYLD Cache
		 * @throws CancelledException If the user canceled the operation
		 */
		public SplitDyldCache(ByteProvider baseProvider, boolean shouldProcessLocalSymbols,
				MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {

			// Setup "base" DYLD Cache
			monitor.setMessage("Parsing " + baseProvider.getName() + " headers...");
			providers.add(baseProvider);
			DyldCacheHeader baseHeader = new DyldCacheHeader(new BinaryReader(baseProvider, true));
			baseHeader.parseFromFile(shouldProcessLocalSymbols, log, monitor);
			headers.add(baseHeader);
			names.add(baseProvider.getName());

			// Setup additional "split" DYLD subcaches (if applicable)
			if (baseHeader.getSubcacheEntries().size() == 0 &&
				baseHeader.getSymbolFileUUID() == null) {
				return;
			}
			Map<String, FSRL> uuidToFileMap = new HashMap<>();
			for (FSRL splitFSRL : findSplitDyldCacheFiles(baseProvider.getFSRL(), monitor)) {
				monitor.setMessage("Parsing " + splitFSRL.getName() + " headers...");
				ByteProvider splitProvider = fsService.getByteProvider(splitFSRL, false, monitor);
				if (!DyldCacheUtils.isDyldCache(splitProvider)) {
					splitProvider.close();
					continue;
				}
				providers.add(splitProvider);
				DyldCacheHeader splitHeader =
					new DyldCacheHeader(new BinaryReader(splitProvider, true));
				splitHeader.parseFromFile(shouldProcessLocalSymbols, log, monitor);
				headers.add(splitHeader);
				names.add(splitFSRL.getName());
				uuidToFileMap.put(NumericUtilities.convertBytesToString(splitHeader.getUUID()),
					splitFSRL);
			}

			// Validate the subcaches
			for (DyldSubcacheEntry subcacheEntry : baseHeader.getSubcacheEntries()) {
				String uuid = subcacheEntry.getUuid();
				String extension = subcacheEntry.getCacheExtension();
				FSRL fsrl = uuidToFileMap.get(uuid);
				if (fsrl == null) {
					throw new IOException("Missing subcache: %s%s".formatted(
						extension != null ? (baseProvider.getName() + extension + " - ") : "",
						uuid));
				}
				log.appendMsg("Including subcache: " + fsrl.getName() + " - " + uuid);
			}
			String symbolUUID =
				NumericUtilities.convertBytesToString(baseHeader.getSymbolFileUUID());
			if (symbolUUID != null) {
				FSRL symbolFSRL = uuidToFileMap.get(symbolUUID);
				if (symbolFSRL == null) {
					throw new IOException("Missing symbols subcache: %s.symbols - %s"
							.formatted(baseProvider.getName(), symbolUUID));
				}
				log.appendMsg(
					"Including symbols subcache: " + symbolFSRL.getName() + " - " + symbolUUID);
			}
		}

		/**
		 * Creates a new {@link SplitDyldCache}
		 * 
		 * @param providers The cache's ordered {@link ByteProvider}s
		 * @param headers The cache's ordered {@link DyldCacheHeader}s
		 * @param names The cache's ordered names
		 * @param log The log
		 * @param monitor A cancelable task monitor
		 */
		public SplitDyldCache(List<ByteProvider> providers, List<DyldCacheHeader> headers,
				List<String> names, MessageLog log, TaskMonitor monitor) {
			this.providers = new ArrayList<>(providers);
			this.headers = new ArrayList<>(headers);
			this.names = new ArrayList<>(names);
		}

		/**
		 * Gets the i'th {@link ByteProvider} in the split DYLD Cache
		 * 
		 * @param i The index of the {@link ByteProvider} to get
		 * @return The i'th {@link ByteProvider} in the split DYLD Cache
		 */
		public ByteProvider getProvider(int i) {
			return providers.get(i);
		}

		/**
		 * Gets the i'th {@link DyldCacheHeader} in the split DYLD Cache
		 * 
		 * @param i The index of the {@link DyldCacheHeader} to get
		 * @return The i'th {@link DyldCacheHeader} in the split DYLD Cache
		 */
		public DyldCacheHeader getDyldCacheHeader(int i) {
			return headers.get(i);
		}

		/**
		 * Gets the i'th {@link String name} in the split DYLD Cache
		 * 
		 * @param i The index of the {@link String name} to get
		 * @return The i'th {@link String name} in the split DYLD Cache
		 */
		public String getName(int i) {
			return names.get(i);
		}

		/**
		 * Gets the number of split DYLD Cache files
		 * 
		 * @return The number of split DYLD Cache files
		 */
		public int size() {
			return providers.size();
		}
		
		/**
		 * Gets the base address of the split DYLD cache.  This is where the cache should be loaded 
		 * in memory.
		 * 
		 * @return The base address of the split DYLD cache
		 */
		public long getBaseAddress() {
			return headers.get(0).getBaseAddress();
		}

		/**
		 * Gets the {@link DyldCacheLocalSymbolsInfo} from the split DYLD Cache files
		 * 
		 * @return The {@link DyldCacheLocalSymbolsInfo} from the split DYLD Cache files, or null 
		 *   if no local symbols are defined
		 */
		public DyldCacheLocalSymbolsInfo getLocalSymbolInfo() {
			return headers.stream()
					.map(h -> h.getLocalSymbolsInfo())
					.filter(info -> info != null)
					.findAny()
					.orElse(null);
		}

		/**
		 * Gets all the {@link DyldCacheImageRecord}s from the entire cache
		 * 
		 * @return A {@link List} of {@link DyldCacheImageRecord}s from the entire cache
		 */
		public List<DyldCacheImageRecord> getImageRecords() {
			return DyldCacheUtils.getImageRecords(headers);
		}

		/**
		 * Gets the Mach-O of the given {@link DyldCacheImageRecord}.
		 * <p>
		 * NOTE: The returned Mach-O is not yet {@link MachHeader#parse(SplitDyldCache) parsed}.
		 * 
		 * @param imageRecord The desired Mach-O's {@link DyldCacheImageRecord} 
		 * @return The {@link DyldCacheImageRecord}'s Mach-O
		 * @throws MachException If there was a problem creating the {@link MachHeader}
		 * @throws IOException If there was an IO-related error
		 */
		public MachHeader getMacho(DyldCacheImageRecord imageRecord)
				throws MachException, IOException {
			int i = imageRecord.splitCacheIndex();
			DyldCacheImage image = imageRecord.image();
			return new MachHeader(providers.get(i),
				image.getAddress() - headers.get(i).getBaseAddress(), false);
		}

		@Override
		public void close() throws IOException {
			// Assume someone else is responsible for closing the base providers that was passed
			// in at construction
			for (int i = 1; i < providers.size(); i++) {
				providers.get(i).close();
			}
		}

		/**
		 * Finds a {@link List} of extra split DYLD Cache {@link FSRL files} to load, sorted by 
		 * name (base DYLD Cache file not included)
		 * 
		 * @param baseFSRL The {@link FSRL} that contains the base DYLD Cache
		 * @return A {@link List} of extra split DYLD Cache {@link FSRL files} to load, sorted by 
		 *   name (base DYLD Cache provider not included).
		 * @throws IOException If there was an IO-related issue finding the files
		 * @throws CancelledException If the user canceled the operation
		 */
		private List<FSRL> findSplitDyldCacheFiles(FSRL baseFSRL, TaskMonitor monitor)
				throws CancelledException, IOException {
			if (baseFSRL == null) {
				return Collections.emptyList();
			}
			try (FileSystemRef fsRef = fsService.getFilesystem(baseFSRL.getFS(), monitor)) {
				GFileSystem fs = fsRef.getFilesystem();
				GFile baseFile = fs.lookup(baseFSRL.getPath());
				String baseName = baseFile.getName();
				List<FSRL> ret = new ArrayList<>();
				for (GFile f : fs.getListing(baseFile.getParentFile())) {
					if (!f.getName().startsWith(baseName + ".")) {
						continue;
					}
					if (f.getName().toLowerCase().endsWith(".map")) {
						continue;
					}
					ret.add(f.getFSRL());
				}
				ret.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));
				return ret;
			}
		}
	}
}
