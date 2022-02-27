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

import java.io.*;
import java.nio.file.AccessMode;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.dyld.DyldArchitecture;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.importer.MessageLog;
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
	 * Class to store a "split" DYLD Cache, which is split across several files (base file, .1, .2,
	 * .symbols, etc).
	 */
	public static class SplitDyldCache implements Closeable {

		List<ByteProvider> providers = new ArrayList<>();
		List<DyldCacheHeader> headers = new ArrayList<>();

		/**
		 * Creates a new {@link SplitDyldCache}
		 * 
		 * @param baseProvider The {@link ByteProvider} of the "base" DYLD Cache file
		 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
		 * @param shouldCombineSplitFiles True if split DYLD Cache files should be automatically 
		 * @param log The log
		 * @param monitor A cancelable task monitor
		 * @throws IOException If there was an IO-related issue with processing the split DYLD Cache
		 * @throws CancelledException If the user canceled the operation
		 */
		public SplitDyldCache(ByteProvider baseProvider, boolean shouldProcessSymbols,
				boolean shouldCombineSplitFiles, MessageLog log, TaskMonitor monitor)
				throws IOException, CancelledException {

			// Setup "base" DYLD Cache
			monitor.setMessage("Parsing " + baseProvider.getName() + " headers...");
			providers.add(baseProvider);
			DyldCacheHeader baseHeader = new DyldCacheHeader(new BinaryReader(baseProvider, true));
			baseHeader.parseFromFile(shouldProcessSymbols, log, monitor);
			headers.add(baseHeader);

			// Setup additional "split" DYLD Caches (if applicable)
			for (File splitFile : getSplitDyldCacheFiles(baseProvider, shouldCombineSplitFiles)) {
				monitor.setMessage("Parsing " + splitFile.getName() + " headers...");
				ByteProvider provider = new FileByteProvider(splitFile, null, AccessMode.READ);
				if (!DyldCacheUtils.isDyldCache(provider)) {
					continue;
				}
				providers.add(provider);
				DyldCacheHeader splitHeader = new DyldCacheHeader(new BinaryReader(provider, true));
				splitHeader.parseFromFile(shouldProcessSymbols, log, monitor);
				headers.add(splitHeader);
				log.appendMsg("Including split DYLD: " + splitFile.getName());
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
		 * Gets a {@link List} of extra split DYLD Cache files to load, sorted by name (base 
		 * DYLD Cache file not included)
		 * 
		 * @param baseProvider The base {@link ByteProvider} that contains the DYLD Cache bytes
		 * @param shouldCombineSplitFiles True if split DYLD Cache files should be automatically 
		 *   combined into one DYLD Cache; false if only the base file should be processed
		 * @return A {@link List} of extra split DYLD Cache files to load, sorted by name (base 
		 *   DYLD Cache file not included).
		 */
		private List<File> getSplitDyldCacheFiles(ByteProvider baseProvider,
				boolean shouldCombineSplitFiles) {
			File file = baseProvider.getFile();
			if (file != null && shouldCombineSplitFiles) {
				String baseName = file.getName();
				File[] splitFiles = file.getParentFile().listFiles(f -> {
					if (!f.getName().startsWith(baseName)) {
						return false;
					}
					if (f.getName().equals(baseName)) {
						return false;
					}
					if (f.getName().toLowerCase().endsWith(".map")) {
						return false;
					}
					return true;
				});
				if (splitFiles != null) {
					List<File> list = Arrays.asList(splitFiles);
					Collections.sort(list);
					return list;
				}
			}
			return Collections.emptyList();
		}
	}
}
