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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

/**
 * An interface for working with function table entries used for exception handling, which are found
 * in the .pdata section.  The actual implementations are architecture-specific.
 */
public interface ImageRuntimeFunctionEntries {

	/**
	 * Marks up an {@link ImageRuntimeFunctionEntries}
	 * 
	 * @param program The {@link Program}
	 * @param start The start {@link Address} 
	 * @throws IOException If there was an IO-related error creating the data
	 * @throws DuplicateNameException If a data type of the same name already exists
	 * @throws CodeUnitInsertionException If data creation failed
	 */
	public void markup(Program program, Address start) throws CodeUnitInsertionException,
			IOException, DuplicateNameException;
}
