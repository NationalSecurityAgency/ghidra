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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.golang.GoConstants;
import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;

@StructureMapping(structureName = {"runtime.imethod", "internal/abi.Imethod"})
public class GoIMethod implements StructureMarkup<GoIMethod> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoIMethod> context;

	@FieldMapping
	@MarkupReference("getGoName")
	@EOLComment("getName")
	private long name;

	@FieldMapping(fieldName = {"ityp", "Typ"})
	@MarkupReference("getType")
	private long ityp;

	@Markup
	public GoName getGoName() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), name);
	}

	public String getName() {
		GoName n = programContext.getSafeName(this::getGoName, this, "unnamed_imethod");
		return n.getName();
	}

	@Markup
	public GoFuncType getType() throws IOException {
		return programContext.getGoTypes()
				.resolveTypeOff(context.getStructureStart(), ityp) instanceof GoFuncType funcType
						? funcType
						: null;
	}

	@Override
	public StructureContext<GoIMethod> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return getName();
	}

	@Override
	public String toString() {
		return String.format("GoIMethod [getName()=%s, getStructureContext()=%s]", getName(),
			getStructureContext());
	}

	public FunctionDefinition getFunctionDefinition(boolean isGeneric, GoTypeManager goTypes)
			throws IOException {
		GoFuncType methodFuncDefType = getType();
		if (methodFuncDefType == null) {
			return null;
		}
		FunctionDefinition funcdef = methodFuncDefType.getFunctionSignature(goTypes);
		List<ParameterDefinition> params = new ArrayList<>(List.of(funcdef.getArguments()));
		params.add(0, new ParameterDefinitionImpl(GoConstants.GOLANG_RECEIVER_PARAM_NAME,
			goTypes.getVoidPtrDT(), null));
		if (isGeneric) {
			params.add(1, new ParameterDefinitionImpl(GoConstants.GOLANG_GENERICS_PARAM_NAME,
				goTypes.getGenericDictDT(), null));
		}
		funcdef.setArguments(params.toArray(ParameterDefinition[]::new));
		return funcdef;
	}

	public static class GoIMethodInfo extends MethodInfo {
		GoItab itab;
		GoIMethod imethod;

		public GoIMethodInfo(GoItab itab, GoIMethod imethod, Address address) {
			super(address);
			this.itab = itab;
			this.imethod = imethod;
		}

		public GoItab getItab() {
			return itab;
		}

		public GoIMethod getImethod() {
			return imethod;
		}
	}
}
/*
struct runtime.imethod // Length: 8  Alignment: 4
{ 
  runtime.nameOff  name   
  runtime.typeOff  ityp       
} pack()
*/
