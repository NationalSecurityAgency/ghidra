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

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Fetches DWARF section data that has been compressed from an underlying {@link DWARFSectionProvider}.
 * <p>
 * Note, this code has not been tested against real data but is included here as it was in 
 * the original DWARF code base.  This section provider is not currently
 * registered in the {@link DWARFSectionProviderFactory} and as such will not be
 * used.
 * <p>
 * TODO: the decompressed data should be stored in something other than in-memory byte arrays,
 * probably should use tmp files.
 */
public class CompressedSectionProvider implements DWARFSectionProvider {

	private final DWARFSectionProvider sp;

	/**
	 * Cache previously decompressed sections, indexed by their normal 'base' name with no
	 * 'z' prefix.
	 */
	private Map<String, ByteProvider> sectionNameToDecompressedSectionDataMap = new HashMap<>();

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
	public ByteProvider getSectionAsByteProvider(String sectionName) throws IOException {
		ByteProvider bp = sp.getSectionAsByteProvider(sectionName);
		if (bp != null) {
			return bp;
		}

		bp = sectionNameToDecompressedSectionDataMap.get(sectionName);
		if (bp != null) {
			return bp;
		}

		bp = sp.getSectionAsByteProvider("z" + sectionName);
		if (bp != null) {
			ByteArrayOutputStream stream = new ByteArrayOutputStream();
			byte[] tempArray = new byte[1024];

			Inflater decompressor = new Inflater();
			decompressor.setInput(bp.readBytes(0, bp.length()));

			while (!decompressor.finished()) {
				try {
					int result = decompressor.inflate(tempArray);
					if (result == 0 && !decompressor.finished()) {
						throw new IOException("Zlib decompressor returned 0 bytes to inflate");
					}
					stream.write(tempArray, 0, result);
				}
				catch (DataFormatException e) {
					throw new IOException(e);
				}
			}

			ByteProvider decompressedBP = new ByteArrayProvider(stream.toByteArray());
			sectionNameToDecompressedSectionDataMap.put(sectionName, decompressedBP);
			return decompressedBP;
		}

		return null;
	}

	@Override
	public void close() {
		sp.close();
		sectionNameToDecompressedSectionDataMap.clear();
	}
}
