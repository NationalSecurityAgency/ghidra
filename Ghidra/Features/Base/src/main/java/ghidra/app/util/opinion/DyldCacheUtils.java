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
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
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
		private FileSystemService fsService;

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
			fsService = FileSystemService.getInstance();
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
				uuidToFileMap.put(splitHeader.getUUID(), splitFSRL);
			}

			// Validate the subcaches
			for (DyldSubcacheEntry subcacheEntry : baseHeader.getSubcacheEntries()) {
				String uuid = subcacheEntry.getUuid();
				String extension = subcacheEntry.getCacheExtension();
				FSRL fsrl = uuidToFileMap.get(uuid);
				if (fsrl != null) {
					log.appendMsg("Including subcache: " + fsrl.getName() + " - " + uuid);
				}
				else {
					log.appendMsg(String.format("Missing subcache: %s%s",
						extension != null ? (baseProvider.getName() + extension + " - ") : "",
						uuid));
				}
			}
			String symbolUUID = baseHeader.getSymbolFileUUID();
			if (symbolUUID != null) {
				FSRL symbolFSRL = uuidToFileMap.get(symbolUUID);
				if (symbolFSRL != null) {
					log.appendMsg(
						"Including symbols subcache: " + symbolFSRL.getName() + " - " + symbolUUID);
				}
				else {
					log.appendMsg(String.format("Missing symbols subcache: %s.symbols - %s",
						baseProvider.getName(), symbolUUID));
				}
			}
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
