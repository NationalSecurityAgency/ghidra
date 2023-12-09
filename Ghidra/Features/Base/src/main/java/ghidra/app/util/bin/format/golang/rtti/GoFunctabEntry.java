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

/**
 * A structure that golang generates that maps between a function's entry point and the
 * location of the function's GoFuncData structure.
 */
@StructureMapping(structureName = "runtime.functab")
public class GoFunctabEntry {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoFunctabEntry> context;

	@FieldMapping(optional = true)
	@MarkupReference("getFuncAddress")
	private long entryoff;	// valid in >=1.18, relative offset of function

	@FieldMapping(optional = true)
	@MarkupReference("getFuncAddress")
	private long entry;	// valid in <=1.17, location of function

	@FieldMapping
	@MarkupReference("getFuncData")
	private long funcoff; // offset into pclntable -> _func

	private Address funcAddress;

	/**
	 * Set the function's entry point using a relative offset.
	 * <p>
	 * Called via deserialization for entryoff fieldmapping annotation.
	 * 
	 * @param entryoff relative offset of the function's entry point
	 */
	public void setEntryoff(long entryoff) {
		this.entryoff = entryoff;

		GoModuledata moduledata = getModuledata();
		this.funcAddress = moduledata != null ? moduledata.getText().add(entryoff) : null;
	}

	/**
	 * Set the function's entry point using the absolute address.
	 * <p>
	 * Called via deserialization for entry fieldmapping annotation.
	 * 
	 * @param entry address of the function's entry point
	 */
	public void setEntry(long entry) {
		this.entry = entry;
		this.funcAddress = programContext.getCodeAddress(entry);
	}

	/**
	 * Returns the address of the function's entry point
	 * 
	 * @return address of the function's entry point
	 */
	public Address getFuncAddress() {
		return funcAddress;
	}

	/**
	 * Return the GoFuncData structure that contains metadata about the function.
	 * 
	 * @return {@link GoFuncData} structure that contains metadata about the function.
	 * @throws IOException if error
	 */
	@Markup
	public GoFuncData getFuncData() throws IOException {
		GoModuledata moduledata = getModuledata();
		return funcoff != 0 && moduledata != null
				? moduledata.getFuncDataInstance(funcoff)
				: null;
	}

	/**
	 * Returns the offset of the GoFuncData structure.
	 * 
	 * @return offset of the GoFuncData structure.
	 */
	public long getFuncoff() {
		return funcoff;
	}

	private GoModuledata getModuledata() {
		return programContext.findContainingModuleByFuncData(context.getStructureStart());
	}
}

