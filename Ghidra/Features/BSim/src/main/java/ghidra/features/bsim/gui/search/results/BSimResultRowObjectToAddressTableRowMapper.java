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

package ghidra.features.bsim.gui.search.results;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.ProgramLocationTableRowMapper;

/**
 * Maps BSimMatchResult objects to Address to get addition table columns
 */
public class BSimResultRowObjectToAddressTableRowMapper
	extends ProgramLocationTableRowMapper<BSimMatchResult, Address> {

	@Override
	public Address map(BSimMatchResult rowObject, Program program,
		ServiceProvider serviceProvider) {
		return rowObject.getAddress();
	}
}
