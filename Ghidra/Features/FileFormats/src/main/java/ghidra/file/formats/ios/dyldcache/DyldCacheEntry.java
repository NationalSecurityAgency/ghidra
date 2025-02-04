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

import com.google.common.collect.RangeSet;

import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;

/**
 * An entry in the {@link DyldCacheFileSystem}
 * 
 * @param path The path of the entry
 * @param splitCacheIndex The entry's {@link SplitDyldCache} index
 * @param rangeSet The entry's address ranges
 * @param mappingInfo The entry's {@link DyldCacheMappingAndSlideInfo}; could be null if this entry
 *   represents a DYLIB
 * @param mappingIndex The entry's {@link DyldCacheMappingAndSlideInfo} index; ignored if the 
 *   {@code mappingInfo} is null.
 */
public record DyldCacheEntry(String path, int splitCacheIndex, RangeSet<Long> rangeSet,
		DyldCacheMappingAndSlideInfo mappingInfo, int mappingIndex) {}
