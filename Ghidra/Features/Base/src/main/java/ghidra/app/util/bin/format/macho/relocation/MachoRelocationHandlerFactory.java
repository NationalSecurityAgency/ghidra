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
package ghidra.app.util.bin.format.macho.relocation;

import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.util.classfinder.ClassSearcher;

/**
 * A class that gets the appropriate Mach-O relocation handler for a specific Mach-O file
 */
public final class MachoRelocationHandlerFactory {

	/**
	 * Gets the appropriate Mach-O relocation handler that is capable of relocating the Mach-O that 
	 * is defined by the given Mach-O header
	 * 
	 * @param header The header associated with the Mach-O to relocate
	 * @return The appropriate Mach-O relocation handler that is capable of relocating the Mach-O 
	 *   that is defined by the given Mach-O header.  Could return null if no such handler was
	 *   found.
	 */
	public final static MachoRelocationHandler getHandler(MachHeader header) {
		return ClassSearcher.getInstances(MachoRelocationHandler.class)
				.stream()
				.filter(h -> h.canRelocate(header))
				.findFirst()
				.orElse(null);
	}
}
