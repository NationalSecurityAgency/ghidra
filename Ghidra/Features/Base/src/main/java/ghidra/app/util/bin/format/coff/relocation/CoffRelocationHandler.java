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

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.CoffFileHeader;
import ghidra.app.util.bin.format.coff.CoffRelocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * An abstract class used to perform COFF relocations.  Classes should extend this class to
 * provide relocations in a machine/processor specific way.
 */
public interface CoffRelocationHandler extends ExtensionPoint {

	/**
	 * Checks to see whether or not an instance of this COFF relocation hander can handle 
	 * relocating the COFF defined by the provided file header.
	 * 
	 * @param fileHeader The file header associated with the COFF to relocate.
	 * @return True if this relocation handler can do the relocation; otherwise, false.
	 */
	public boolean canRelocate(CoffFileHeader fileHeader);

	/**
	 * Performs a relocation at the specified address.
	 * 
	 * @param address The address at which to perform the relocation.
	 * @param relocation The relocation information to use to perform the relocation.
	 * @param relocationContext relocation context data
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException If there is a problem accessing memory during the relocation.
	 * @throws RelocationException if supported relocation encountered an error during processing.
	 * This exception should be thrown in place of returning {@link RelocationResult#FAILURE} or
	 * a status of {@link Status#FAILURE} which will facilitate a failure reason via 
	 * {@link RelocationException#getMessage()}.
	 */
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, RelocationException;

}
