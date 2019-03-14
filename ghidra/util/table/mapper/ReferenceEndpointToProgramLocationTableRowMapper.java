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
package ghidra.util.table.mapper;

import docking.widgets.table.TableRowMapper;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.field.ReferenceEndpoint;

public class ReferenceEndpointToProgramLocationTableRowMapper
		extends TableRowMapper<ReferenceEndpoint, ProgramLocation, Program> {

	@Override
	public ProgramLocation map(ReferenceEndpoint rowObject, Program data, ServiceProvider sp) {
		return new ProgramLocation(data, rowObject.getAddress());
	}
}
