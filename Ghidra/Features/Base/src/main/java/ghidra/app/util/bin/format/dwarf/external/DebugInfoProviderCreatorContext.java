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
package ghidra.app.util.bin.format.dwarf.external;

import ghidra.program.model.listing.Program;

/**
 * Information that might be needed to create a new {@link DebugInfoProvider} instance.
 * 
 * @param registry {@link DebugInfoProviderRegistry}
 * @param program {@link Program}
 */
public record DebugInfoProviderCreatorContext(DebugInfoProviderRegistry registry, Program program) {}
