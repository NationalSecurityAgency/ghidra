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
package ghidra.app.util.bin.format.coff.relocation;

import ghidra.app.util.bin.format.coff.CoffFileHeader;
import ghidra.util.classfinder.ClassSearcher;

/**
 * A class that gets the appropriate COFF relocation handler for a specific COFF.
 */
public final class CoffRelocationHandlerFactory {

	/**
	 * Gets the appropriate COFF relocation handler that is capable of relocating the COFF that is
	 * defined by the given COFF file header.
	 * 
	 * @param fileHeader The file header associated with the COFF to relocate.
	 * @return The appropriate COFF relocation handler that is capable of relocating the COFF that 
	 *     is defined by the given COFF file header.  Could return null if there if no such handler
	 *     was found.
	 */
	public final static CoffRelocationHandler getHandler(CoffFileHeader fileHeader) {
		for (CoffRelocationHandler handler : ClassSearcher.getInstances(
			CoffRelocationHandler.class)) {
			if (handler.canRelocate(fileHeader)) {
				return handler;
			}
		}
		return null;
	}
}
