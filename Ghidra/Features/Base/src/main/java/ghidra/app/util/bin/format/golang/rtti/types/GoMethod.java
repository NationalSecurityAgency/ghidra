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

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.util.NumericUtilities;

/**
 * Structure that defines a method for a GoType, found in the type's {@link GoUncommonType} struct.
 */
@StructureMapping(structureName = "runtime.method")
public class GoMethod implements StructureMarkup<GoMethod> {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoMethod> context;

	@FieldMapping
	@MarkupReference("getGoName")
	@EOLComment("getName")
	private long name;	// nameOff

	@FieldMapping
	@MarkupReference("getType")
	private long mtyp;	// typeOff - function definition

	@FieldMapping
	@MarkupReference
	private long ifn;	// textOff, address of version of method called via the interface

	@FieldMapping
	@MarkupReference
	private long tfn;	// textOff, address of version of method called normally

	/**
	 * Returns the name of this method.
	 * 
	 * @return name of this method as a raw GoName value
	 * @throws IOException if error reading
	 */
	@Markup
	public GoName getGoName() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), name);
	}

	/**
	 * Returns the name of this method.
	 * 
	 * @return name of this method
	 */
	public String getName() {
		GoName n = programContext.getSafeName(this::getGoName, this, "unnamed_method");
		return n.getName();
	}

	/**
	 * Returns true if the funcdef is missing for this method.
	 * 
	 * @return true if the funcdef is missing for this method
	 */
	public boolean isSignatureMissing() {
		return mtyp == 0 || mtyp == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG || mtyp == -1;
	}

	/**
	 * Return the {@link GoType} that defines the funcdef / func signature.
	 * 
	 * @return {@link GoType} that defines the funcdef / func signature
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoType getType() throws IOException {
		return programContext.resolveTypeOff(context.getStructureStart(), mtyp);
	}

	@Override
	public StructureContext<GoMethod> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() {
		return getName();
	}

	/**
	 * Returns the address of the version of the function that is called via the interface.
	 * 
	 * @return address of the version of the function that is called via the interface
	 */
	public Address getIfn() {
		return programContext.resolveTextOff(context.getStructureStart(), ifn);
	}

	/**
	 * Returns the address of the version of the function that is called normally.
	 * 
	 * @return address of the version of the function that is called normally
	 */
	public Address getTfn() {
		return programContext.resolveTextOff(context.getStructureStart(), tfn);
	}

	/**
	 * Returns a list of {@link GoMethodInfo}s containing the ifn and tfn values (if present).
	 * 
	 * @param containingType {@link GoType} that contains this method
	 * @return list of {@link GoMethodInfo} instances representing the ifn and tfn values if present
	 */
	public List<GoMethodInfo> getMethodInfos(GoType containingType) {
		List<GoMethodInfo> results = new ArrayList<>(2);
		Address addr = getTfn();
		if (addr != null) {
			results.add(new GoMethodInfo(containingType, this, addr));
		}
		addr = getIfn();
		if (addr != null) {
			results.add(new GoMethodInfo(containingType, this, addr));
		}
		return results;
	}

	@Override
	public String toString() {
		return String.format(
			"GoMethod [context=%s, getName()=%s, getIfn()=%s, getTfn()=%s]", context, getName(),
			getIfn(), getTfn());
	}

	//----------------------------------------------------------------------------------------

	public class GoMethodInfo extends MethodInfo {
		GoType type;
		GoMethod method;

		public GoMethodInfo(GoType type, GoMethod method, Address address) {
			super(address);
			this.type = type;
			this.method = method;
		}

		public GoType getType() {
			return type;
		}

		public GoMethod getMethod() {
			return method;
		}

		public boolean isIfn(Address funcAddr) {
			return funcAddr.equals(method.getIfn());
		}

		public boolean isTfn(Address funcAddr) {
			return funcAddr.equals(method.getTfn());
		}

		@Override
		public FunctionDefinition getSignature() throws IOException {
			return type.getMethodSignature(method, false);
		}

		public FunctionDefinition getPartialSignature() throws IOException {
			return type.getMethodSignature(method, true);
		}

	}
}
