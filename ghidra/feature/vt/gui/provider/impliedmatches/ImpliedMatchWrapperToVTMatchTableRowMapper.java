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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.table.ProgramLocationTableRowMapper;

/**
 * A {@link ProgramLocationTableRowMapper} that allows us to map this package's table row objects to 
 * Match objects.   This allows us to reuse the columns from the match table.
 */
public class ImpliedMatchWrapperToVTMatchTableRowMapper extends
		ProgramLocationTableRowMapper<ImpliedMatchWrapperRowObject, VTMatch> {

	@Override
	public VTMatch map(ImpliedMatchWrapperRowObject rowObject, Program program,
			ServiceProvider serviceProvider) {
		return new MatchMapper(rowObject);
	}

}
