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
package ghidra.feature.vt.gui.provider.functionassociation;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.ProgramLocationTableRowMapper;

public class FunctionRowObjectToProgramLocationTableRowMapper extends
		ProgramLocationTableRowMapper<VTFunctionRowObject, ProgramLocation> {

	@Override
	public ProgramLocation map(VTFunctionRowObject rowObject, Program program,
			ServiceProvider serviceProvider) {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionAssociationInfo info = rowObject.getInfo();
		Function function = functionManager.getFunction(info.getFunctionID());
		return new FunctionSignatureFieldLocation(program, function.getEntryPoint(), null, 0,
			function.getPrototypeString(false, false));
	}

}
