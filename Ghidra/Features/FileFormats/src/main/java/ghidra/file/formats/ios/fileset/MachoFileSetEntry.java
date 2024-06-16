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
package ghidra.file.formats.ios.fileset;

/**
 * An entry in the {@link MachoFileSetFileSystem}
 * 
 * @param id The id of the entry
 * @param offset The offset of the entry in the provider
 * @param isBranchSegment True if this entry represents a branch segment; false if it represents
 *   an LC_FILESET_ENTRY Mach-O
 */
public record MachoFileSetEntry(String id, long offset, boolean isBranchSegment) {}
