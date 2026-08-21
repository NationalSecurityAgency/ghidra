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
package ghidra.app.util.bin.format.pe.dvrt;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.PeMarkupable;

/**
 * An abstract dynamic value relocation header
 */
public abstract class AbstractImageDynamicRelocationHeader
		implements StructConverter, PeMarkupable {

	protected long rva;

	/**
	 * Creates a new {@link AbstractImageDynamicRelocationHeader}
	 * 
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public AbstractImageDynamicRelocationHeader(long rva) throws IOException {
		this.rva = rva;
	}
}
