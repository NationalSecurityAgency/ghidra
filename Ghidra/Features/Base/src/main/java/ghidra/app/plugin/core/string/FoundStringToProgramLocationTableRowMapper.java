/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.string;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.string.FoundString;
import ghidra.util.table.ProgramLocationTableRowMapper;

public class FoundStringToProgramLocationTableRowMapper extends
		ProgramLocationTableRowMapper<FoundString, ProgramLocation> {

	@Override
	public ProgramLocation map(FoundString rowObject, Program data, ServiceProvider serviceProvider) {
		return new ProgramLocation(data, rowObject.getAddress());
	}

}
