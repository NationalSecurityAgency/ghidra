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
 * @param processLocalSymbols True if local symbols should be processes; otherwise, false
 * @param markupLocalSymbols True if local symbols should be marked up; otherwise, false
 * @param processExports True if exported symbols should be processed; otherwise, false
 * @param processChainedFixups True if chained fixups should be processed; otherwise, false
 * @param addChainedFixupsRelocations True if chained fixups should be added to the relocation
 *   table; otherwise false
 * @param markupMachoLoadCommandData True if individual Mach-O load command data blocks should be
 *   marked up; otherwise, false
 */
public record DyldCacheOptions(boolean processLocalSymbols, boolean markupLocalSymbols,
		boolean processExports, boolean processChainedFixups, boolean addChainedFixupsRelocations,
		boolean markupMachoLoadCommandData) {
}
