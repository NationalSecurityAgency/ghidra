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

import java.io.File;
import java.io.IOException;
import java.util.Map;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo;
import ghidra.app.util.bin.format.macho.dyld.DyldFixup;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link ByteProvider} that provides slid dyld_shared_cache bytes for a given 
 * {@link DyldCacheMappingInfo byte mapping}
 */
public class DyldCacheSlidProvider implements ByteProvider {

	private String name;
	private ByteProvider origProvider;
	private DyldCacheMappingInfo mappingInfo;
	private Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap;
	private TaskMonitor monitor;

	/**
	 * Creates a new {@link DyldCacheSlidProvider}
	 * 
	 * @param mappingInfo The {@link DyldCacheMappingInfo} that is being requested
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param splitCacheIndex The mapping's {@link SplitDyldCache} index
	 * @param slideFixupMap A {@link Map} of {@link DyldFixup}s to perform
	 * @param monitor A {@link TaskMonitor} to monitor the reads
	 */
	public DyldCacheSlidProvider(DyldCacheMappingInfo mappingInfo, SplitDyldCache splitDyldCache,
			int splitCacheIndex, Map<DyldCacheMappingInfo, Map<Long, DyldFixup>> slideFixupMap,
			TaskMonitor monitor) {
		this.name = splitDyldCache.getName(splitCacheIndex);
		this.origProvider = splitDyldCache.getProvider(splitCacheIndex);
		this.mappingInfo = mappingInfo;
		this.slideFixupMap = slideFixupMap;
		this.monitor = monitor;
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (!mappingInfo.contains(index, false)) {
			return origProvider.readByte(index);
		}
		Map<Long, DyldFixup> fixups = slideFixupMap.get(mappingInfo);
		if (fixups == null) {
			return origProvider.readByte(index);
		}
		long aligned = index & ~3;
		DyldFixup fixup = fixups.get(aligned);
		if (fixup == null) {
			aligned = index & ~7;
			fixup = fixups.get(aligned);
			if (fixup != null && fixup.size() != 8) {
				fixup = null;
			}
		}
		if (fixup == null) {
			return origProvider.readByte(index);
		}
		return (byte) (fixup.value() >> ((index - aligned) * 8));
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (length < 0 || length > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("unsupported length");
		}
		if (index < 0) {
			throw new IllegalArgumentException("invalid index");
		}
		byte[] ret = new byte[(int) length];
		monitor.initialize(length, "Reading " + name);
		// TODO: spped this up by using super.readBytes() to read the chunks that don't contain fixups
		for (int i = 0; i < length; i++) {
			monitor.incrementProgress();
			ret[i] = readByte(index + i);
		}
		return ret;
	}

	@Override
	public File getFile() {
		return origProvider.getFile();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getAbsolutePath() {
		return origProvider.getAbsolutePath();
	}

	@Override
	public long length() throws IOException {
		return origProvider.length();
	}

	@Override
	public boolean isValidIndex(long i) {
		return origProvider.isValidIndex(i);
	}

	@Override
	public void close() throws IOException {
		// This is a wrapper, so don't close
	}
}
