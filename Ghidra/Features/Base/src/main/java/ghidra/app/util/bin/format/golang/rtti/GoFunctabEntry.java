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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;

@StructureMapping(structureName = "runtime.functab")
public class GoFunctabEntry {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoFunctabEntry> context;

	@FieldMapping
	@MarkupReference("funcAddress")
	private long entryoff;	// offset relative to module's .text

	@FieldMapping
	@MarkupReference("funcData")
	private long funcoff; // offset into pclntable -> _func

	public Address getFuncAddress() {
		return getModuledata().getText().add(entryoff);
	}

	@Markup
	public GoFuncData getFuncData() throws IOException {
		return funcoff != 0 ? getModuledata().getFuncDataInstance(funcoff) : null;
	}

	private GoModuledata getModuledata() {
		return programContext.findContainingModuleByFuncData(context.getStructureStart());
	}
}

