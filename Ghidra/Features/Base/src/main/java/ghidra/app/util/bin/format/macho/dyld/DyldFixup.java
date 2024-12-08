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
package ghidra.app.util.bin.format.macho.dyld;

import ghidra.program.model.symbol.Symbol;

/**
 * Stores information needed to perform a dyld pointer fixup
 * 
 * @param offset The offset of where to perform the fixup (from some base address/index)
 * @param value The fixed up value
 * @param size The size of the fixup in bytes
 * @param symbol The {@link Symbol} associated with the fixup (could be null)
 * @param libOrdinal The library ordinal associated with the fixup (could be null)
 */
public record DyldFixup(long offset, long value, int size, Symbol symbol, Integer libOrdinal) {}
