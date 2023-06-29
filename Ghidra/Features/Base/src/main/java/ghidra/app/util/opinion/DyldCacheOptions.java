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

/**
 * Options from the {@link DyldCacheLoader}
 * 
 * @param processChainedFixups True if chained fixups should be processed; otherwise, false
 * @param addChainedFixupsRelocations True if chained fixups should be added to the relocation
 *   table; otherwise false
 * @param processLocalSymbols True if local symbols should be processes; otherwise, false
 * @param markupLocalSymbols True if local symbols should be marked up; otherwise, false
 * @param processDylibMemory True if individual dylib memory should be processed; otherwise, false
 * @param processDylibSymbols True if individual dylib symbols should be processed; otherwise, false
 * @param processDylibExports True if individual dylib exports should be processed; otherwise, false
 * @param markupDylibLoadCommandData True if individual dylib load command data blocks should be
 *   marked up; otherwise, false
 * @param processLibobjc True if special libobjc should occur; otherwise, false
 */
public record DyldCacheOptions(boolean processChainedFixups, boolean addChainedFixupsRelocations,
		boolean processLocalSymbols, boolean markupLocalSymbols, boolean processDylibMemory,
		boolean processDylibSymbols, boolean processDylibExports,
		boolean markupDylibLoadCommandData, boolean processLibobjc) {
}
