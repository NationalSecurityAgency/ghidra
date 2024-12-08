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
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.util.bin.format.golang.rtti.types.*;
import ghidra.app.util.bin.format.golang.rtti.types.GoIMethod.GoIMethodInfo;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.util.Msg;

/**
 * Represents a mapping between a golang interface and a type that implements the methods of
 * the interface.
 */
@PlateComment
@StructureMapping(structureName = "runtime.itab")
public class GoItab implements StructureMarkup<GoItab> {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoItab> context;

	@FieldMapping
	@MarkupReference("getInterfaceType")
	long inter;	// runtime.interfacetype * 

	@FieldMapping
	@MarkupReference("getType")
	long _type;	// runtime._type *

	@FieldMapping
	long fun;	// inline varlen array, specd as uintptr[1], we are treating as simple long 

	/**
	 * Returns the interface implemented by the specified type.
	 * 
	 * @return interface implemented by the specified type
	 * @throws IOException if error reading ref'd interface structure
	 */
	@Markup
	public GoInterfaceType getInterfaceType() throws IOException {
		return programContext.readStructure(GoInterfaceType.class, inter);
	}

	/**
	 * Returns the type that implements the specified interface.
	 * 
	 * @return type that implements the specified interface
	 * @throws IOException if error reading the ref'd type structure
	 */
	@Markup
	public GoType getType() throws IOException {
		return programContext.getGoType(_type);
	}

	/**
	 * Return the number of methods implemented.
	 * 
	 * @return number of methods implemented
	 * @throws IOException if error reading interface structure
	 */
	public long getFuncCount() throws IOException {
		GoInterfaceType iface = getInterfaceType();
		GoSlice methods = iface.getMethodsSlice();
		return Math.max(1, methods.getLen());
	}

	/**
	 * Returns an artificial slice that contains the address of the functions that implement
	 * the interface methods.
	 * 
	 * @return artificial slice that contains the address of the functions that implement
	 * the interface methods
	 * @throws IOException if error reading method info
	 */
	public GoSlice getFunSlice() throws IOException {
		long funcCount = getFuncCount();
		long funOffset = context.getStructureEnd() - programContext.getPtrSize();
		return new GoSlice(funOffset, funcCount, funcCount, programContext);
	}

	private Map<Address, GoIMethod> getInterfaceMethods() throws IOException {
		long[] functionAddrs = getFunSlice().readUIntList(programContext.getPtrSize());
		GoInterfaceType iface = getInterfaceType();
		List<GoIMethod> ifaceMethods = iface.getMethods();
		if (functionAddrs.length != ifaceMethods.size()) {
			Msg.warn(this, "Bad interface spec: %s, iface length doesn't match function impl list"
					.formatted(getStructureLabel()));
			return Map.of();
		}
		Map<Address, GoIMethod> results = new HashMap<>();
		for (int i = 0; i < functionAddrs.length; i++) {
			if (functionAddrs[i] == 0) {
				continue;
			}
			Address addr = programContext.getCodeAddress(functionAddrs[i]);
			if (!programContext.getProgram()
					.getMemory()
					.getLoadedAndInitializedAddressSet()
					.contains(addr)) {
				continue;
			}
			GoIMethod imethod = ifaceMethods.get(i);

			results.put(addr, imethod);
		}
		return results;
	}

	/**
	 * Returns list of {@link GoIMethodInfo} instances, that represent the methods implemented by
	 * the specified type / interface.
	 * 
	 * @return list of {@link GoIMethodInfo} instances
	 * @throws IOException if error reading interface method list
	 */
	public List<GoIMethodInfo> getMethodInfoList() throws IOException {
		List<GoIMethodInfo> results = new ArrayList<>();
		for (Entry<Address, GoIMethod> entry : getInterfaceMethods().entrySet()) {
			results.add(new GoIMethodInfo(this, entry.getValue(), entry.getKey()));
		}
		return results;
	}

	/**
	 * Returns a {@link FunctionDefinition} for the specified method of this itab.
	 * 
	 * @param imethod info about an interface method
	 * @return {@link FunctionDefinition} for the specified method of this itab
	 * @throws IOException if error reading required info
	 */
	public FunctionDefinition getSignatureFor(GoIMethod imethod) throws IOException {
		GoType receiverType = getType();
		DataType receiverDT = programContext.getRecoveredType(receiverType);

		GoType methodType = imethod.getType();
		if (methodType == null) {
			return null;
		}
		return programContext.getSpecializedMethodSignature(imethod.getName(), methodType,
			receiverDT, false);
	}

	@Override
	public String getStructureName() throws IOException {
		return "%s__implements__%s".formatted(getType().getName(),
			getInterfaceType().getName());
	}

	@Override
	public StructureContext<GoItab> getStructureContext() {
		return context;
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException {
		GoSlice funSlice = getFunSlice();
		List<Address> funcAddrs = Arrays.stream(funSlice.readUIntList(programContext.getPtrSize()))
				.mapToObj(offset -> programContext.getCodeAddress(offset))
				.toList();
		// this adds references from the elements of the artificial slice.  However, the reference
		// from element[0] of the real "fun" array won't show anything in the UI even though
		// there is a outbound reference there.
		funSlice.markupElementReferences(programContext.getPtrSize(), funcAddrs, session);

		GoSlice extraFunSlice =
			funSlice.getSubSlice(1, funSlice.getLen() - 1, programContext.getPtrSize());
		extraFunSlice.markupArray(getStructureName() + "_extra_itab_functions", null,
			(DataType) null, true, session);
	}

	@Override
	public String toString() {
		try {
			GoInterfaceType ifaceType = getInterfaceType();
			String s =
				"itab for %s implements %s".formatted(getType().getName(),
					ifaceType.getName());
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
