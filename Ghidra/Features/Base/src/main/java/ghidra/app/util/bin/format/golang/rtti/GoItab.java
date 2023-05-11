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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;

@PlateComment
@StructureMapping(structureName = "runtime.itab")
public class GoItab implements StructureMarkup<GoItab> {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoItab> context;

	@FieldMapping
	@MarkupReference("interfaceType")
	long inter;	// runtime.interfacetype * 

	@FieldMapping
	@MarkupReference("type")
	long _type;	// runtime._type *

	@FieldMapping
	long fun;	// inline varlen array, specd as uintptr[1], we are treating as simple long 

	@Markup
	public GoInterfaceType getInterfaceType() throws IOException {
		return programContext.readStructure(GoInterfaceType.class, inter);
	}

	@Markup
	public GoType getType() throws IOException {
		return programContext.getGoType(_type);
	}

	public long getFuncCount() throws IOException {
		GoInterfaceType iface = getInterfaceType();
		GoSlice methods = iface.getMethodsSlice();
		return Math.max(1, methods.getLen());
	}

	public GoSlice getFunSlice() throws IOException {
		long funcCount = getFuncCount();
		long funOffset = context.getStructureEnd() - programContext.getPtrSize();
		return new GoSlice(funOffset, funcCount, funcCount, programContext);
	}

	@Override
	public String getStructureName() throws IOException {
		return getInterfaceType().getStructureName();
	}

	@Override
	public StructureContext<GoItab> getStructureContext() {
		return context;
	}

	@Override
	public void additionalMarkup() throws IOException {
		GoSlice funSlice = getFunSlice();
		List<Address> funcAddrs = Arrays.stream(funSlice.readUIntList(programContext.getPtrSize()))
				.mapToObj(offset -> programContext.getCodeAddress(offset))
				.collect(Collectors.toList());
		// this adds references from the elements of the artificial slice.  However, the reference
		// from element[0] of the real "fun" array won't show anything in the UI even though
		// there is a outbound reference there.
		funSlice.markupElementReferences(programContext.getPtrSize(), funcAddrs);

		GoSlice extraFunSlice =
			funSlice.getSubSlice(1, funSlice.getLen() - 1, programContext.getPtrSize());
		extraFunSlice.markupArray(getStructureName() + "_extra_itab_functions", (DataType) null,
			true);
	}

	@Override
	public String toString() {
		try {
			String s = "itab for " + getStructureName();
			GoInterfaceType ifaceType = getInterfaceType();
			String methodListString = ifaceType.getMethodListString();
			if (!methodListString.isEmpty()) {
				s += "\n// Methods\n" + methodListString;
			}
			return s;
		}
		catch (IOException e) {
			return super.toString();
		}
	}

}
/*
struct runtime.itab  
Length: 20  Alignment: 4
{ 
  runtime.interfacetype *  inter    
  runtime._type *                _type   
  uint32                                hash    
  uint8[4]                             _          
  uintptr[1]                         fun       
} pack()
*/
