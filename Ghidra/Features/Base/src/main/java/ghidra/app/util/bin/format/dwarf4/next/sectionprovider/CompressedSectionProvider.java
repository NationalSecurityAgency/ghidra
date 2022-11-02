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
package ghidra.app.util.bin.format.dwarf4.next.sectionprovider;

import java.util.HashMap;
import java.util.Map;
import java.util.zip.InflaterInputStream;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A wrapper around another DWARFSectionProvider, this provider
 * fetches DWARF section data that has been compressed and stored in sections in the underlying 
 * {@link DWARFSectionProvider}.
 * <p>
 */
public class CompressedSectionProvider implements DWARFSectionProvider {
	private static final int ZLIB_MAGIC_BE = 0x5a4c4942;	// "ZLIB"

	private final DWARFSectionProvider sp;

	/**
	 * Cache previously decompressed sections, indexed by their normal 'base' name with no
	 * 'z' prefix.
	 */
	private Map<String, ByteProvider> decompressedSectionCache = new HashMap<>();

	public CompressedSectionProvider(DWARFSectionProvider sp) {
		this.sp = sp;
	}

	@Override
	public boolean hasSection(String... sectionNames) {
		if (sp.hasSection(sectionNames)) {
			return true;
		}

		for (String sectionName : sectionNames) {
			if (!sp.hasSection("z" + sectionName)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName, TaskMonitor monitor)
			throws IOException {
		ByteProvider bp = sp.getSectionAsByteProvider(sectionName, monitor);
		if (bp != null) {
			return bp;
		}

		bp = decompressedSectionCache.get(sectionName);
		if (bp != null) {
			return bp;
		}

		bp = sp.getSectionAsByteProvider("z" + sectionName, monitor);
		if (bp != null) {
			FileSystemService fsService = FileSystemService.getInstance();
			try (
					InputStream is = getInputStreamForCompressedSection(bp);
					FileCacheEntryBuilder tmpFile = fsService.createTempFile(bp.length())) {

				FSUtilities.streamCopy(is, tmpFile, monitor);

				FileCacheEntry fce = tmpFile.finish();
				ByteProvider decompressedBP =
					fsService.getNamedTempFile(fce, "uncompressed_" + sectionName);
				decompressedSectionCache.put(sectionName, decompressedBP);

				return decompressedBP;
			}
			catch (CancelledException e) {
				// fall thru
			}
		}

		return null;
	}

	private InputStream getInputStreamForCompressedSection(ByteProvider compressedBP)
			throws IOException {
		BinaryReader reader = new BinaryReader(compressedBP, false /* BE */);
		int magic = reader.readInt(0);
		if (magic == ZLIB_MAGIC_BE) {
			//long size = reader.readLong(4); // can't use size right now, but here it is if need it
			int streamStart = 12; // sizeof(magic) + sizeof(long)
			return new InflaterInputStream(compressedBP.getInputStream(streamStart));
		}
		throw new IOException("Unknown compressed section format: " + Integer.toHexString(magic));
	}

	@Override
	public void close() {
		for (ByteProvider bp : decompressedSectionCache.values()) {
			FSUtilities.uncheckedClose(bp, null);
		}
		decompressedSectionCache.clear();
		sp.close();
	}
}
