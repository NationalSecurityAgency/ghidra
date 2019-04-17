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
package ghidra.feature.fid.service;

import ghidra.feature.fid.db.LibraryRecord;
import ghidra.program.model.address.Address;

/**
 * FidMatch is a container that holds the results of a FidService search,
 * comprised of the full path within the storage API where it's located.
 *
 */
public interface FidMatch extends FidMatchScore {
	/**
	 * Returns the actual entry point of the matched function (in the searched program, not the FID library).
	 * @return the entry point of the matched function
	 */
	Address getMatchedFunctionEntryPoint();

	/**
	 * Returns the library record for the potential match.
	 * @return the library record
	 */
	LibraryRecord getLibraryRecord();
}
