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
import java.util.*;

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.rtti.types.GoMethod.GoMethodInfo;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Common abstract base class for GoType classes
 */
@PlateComment()
public abstract class GoType implements StructureMarkup<GoType>, StructureVerifier {
	//@formatter:off
	private static final Map<GoKind, Class<? extends GoType>> specializedTypeClasses =
		Map.ofEntries(
			Map.entry(GoKind.Struct, GoStructType.class),
			Map.entry(GoKind.Pointer, GoPointerType.class),
			Map.entry(GoKind.Func, GoFuncType.class),
			Map.entry(GoKind.Slice, GoSliceType.class),
			Map.entry(GoKind.Array, GoArrayType.class),
			Map.entry(GoKind.Chan, GoChanType.class),
			Map.entry(GoKind.Map, GoMapType.class),
			Map.entry(GoKind.Interface, GoInterfaceType.class));
	//@formatter:on

	/**
	 * Returns the specific GoType derived class that will handle the go type located at the
	 * specified offset.
	 * 
	 * @param programContext program-level mapper context
	 * @param offset absolute location of go type struct
	 * @return GoType class that will best handle the type struct
	 * @throws IOException if error reading
	 */
	public static Class<? extends GoType> getSpecializedTypeClass(GoRttiMapper programContext,
			long offset) throws IOException {
		GoTypeDetector typeDetector = programContext.readStructure(GoTypeDetector.class, offset);
		Class<? extends GoType> result = specializedTypeClasses.get(typeDetector.getKind());
		if (result == null) {
			result = GoPlainType.class;
		}
		return result;
	}

	@ContextField
	protected GoRttiMapper programContext;

	@ContextField
	protected StructureContext<GoType> context;

	@FieldMapping(fieldName = {"typ", "Type"})
	@Markup
	@FieldOutput
	protected GoBaseType typ;

	protected GoUncommonType uncommonType;

	protected GoBaseType getBaseType() {
		return typ;
	}

	/**
	 * Returns the starting offset of this type, used as an identifier.
	 * 
	 * @return starting offset of this type
	 */
	public long getTypeOffset() {
		return context.getStructureStart();
	}

	/**
	 * Returns the name of this type.
	 * 
	 * @return name of this type
	 */
	public String getName() {
		return typ.getName();
	}

	public GoSymbolName getSymbolName() {
		return GoSymbolName.parseTypeName(getName(), getPackagePathString());
	}
	
	public String getFullyQualifiedName() {
		return getSymbolName().asString();
	}

	/**
	 * Returns the package path of this type.
	 * 
	 * @return package path of this type
	 */
	public String getPackagePathString() {
		try {
			return typ.hasUncommonType() ? getUncommonType().getPackagePathString() : "";
		}
		catch (IOException e) {
			return "";
		}
	}

	public String getDebugId() {
		return "%s@%s".formatted(context.getMappingInfo().getDescription(),
			context.getStructureAddress());
	}

	protected long getOffsetEndOfFullType() {
		return context.getStructureEnd() + (typ.hasUncommonType()
				? programContext.getStructureMappingInfo(GoUncommonType.class).getStructureLength()
				: 0);
	}

	/**
	 * Returns the location of where this type object, and any known associated optional
	 * structures ends.
	 * 
	 * @return index location of end of this type object
	 * @throws IOException if error reading
	 */
	public long getEndOfTypeInfo() throws IOException {
		return typ.hasUncommonType()
				? getUncommonType().getEndOfTypeInfo()
				: context.getStructureEnd();
	}

	@Markup
	public GoUncommonType getUncommonType() throws IOException {
		if (uncommonType == null && typ.hasUncommonType()) {
			uncommonType =
				programContext.readStructure(GoUncommonType.class, context.getStructureEnd());
		}
		return uncommonType;
	}

	/**
	 * Returns a list of all methods defined on this type.  Methods that specify both a
	 * "tfn" address as well as a "ifn" address will be represented twice.
	 * 
	 * @return list of MethodInfo's
	 * @throws IOException if error reading
	 */
	public List<GoMethodInfo> getMethodInfoList() throws IOException {
		List<GoMethodInfo> results = new ArrayList<>();
		GoUncommonType ut = getUncommonType();
		List<GoMethod> methods;
		if (ut != null && (methods = ut.getMethods()) != null) {
			for (GoMethod method : methods) {
				results.addAll(method.getMethodInfos(this));
			}
		}
		return results;
	}

	@Override
	public StructureContext<GoType> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureLabel() throws IOException {
		return "%s___%s_type".formatted(getFullyQualifiedName(), typ.getKind().toString());
	}

	@Override
	public String getStructureName() throws IOException {
		return getFullyQualifiedName();
	}

	@Override
	public String getStructureNamespace() throws IOException {
		return getPackagePathString();
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		GoUncommonType ut = getUncommonType();
		if (ut != null) {
			GoSlice slice = ut.getMethodsSlice();
			slice.markupArray(getStructureLabel() + "_methods", getStructureNamespace(),
				GoMethod.class, false, session);
			slice.markupArrayElements(GoMethod.class, session);
			session.labelStructure(ut, getStructureLabel() + "_uncommon", getStructureNamespace());
		}
	}

	protected String getImplementsInterfaceString() {
		StringBuilder sb = new StringBuilder();
		for (GoItab goItab : programContext.getGoTypes().getInterfacesImplementedByType(this)) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			try {
				sb.append(AddressAnnotatedStringHandler.createAddressAnnotationString(
					goItab.getInterfaceType().getStructureContext().getStructureAddress(),
					goItab.getInterfaceType().getFullyQualifiedName()));
				sb.append(" ");
				sb.append(AddressAnnotatedStringHandler.createAddressAnnotationString(
					goItab.getStructureContext().getStructureAddress(), "[itab]"));
			}
			catch (IOException e) {
				sb.append("unknown_interface");
			}
		}
		return sb.toString();
	}

	protected String getMethodListString() throws IOException {
		GoUncommonType ut = getUncommonType();
		if (ut == null || uncommonType.mcount == 0) {
			return "";
		}
		GoType ptrType = typ.getPtrToThis();
		GoSymbolName ptrSymbolName = ptrType != null ? ptrType.getSymbolName() : null;
		String ptrTypeName = ptrSymbolName != null ? ptrSymbolName.getBaseTypeName() : null;
		
		StringBuilder sb = new StringBuilder();
		for (GoMethod method : ut.getMethods()) {
			GoFuncType methodFuncDef = method.getType() instanceof GoFuncType funcType ? funcType : null;
			Address tfnAddr = method.getTfn();
			if (tfnAddr != null) {
				String tfnStr = getMethodPrototypeString(method.getName(),methodFuncDef );
				sb.append(!sb.isEmpty() ? "\n" : "")
						.append(AddressAnnotatedStringHandler.createAddressAnnotationString(tfnAddr,
							tfnStr));
			}
			Address ifnAddr = method.getIfn();
			if (ifnAddr != null && ptrTypeName != null) {
				String ifnStr = getMethodPrototypeString(ptrTypeName, method.getName(), methodFuncDef);
				sb.append(!sb.isEmpty() ? "\n" : "")
						.append(AddressAnnotatedStringHandler.createAddressAnnotationString(ifnAddr, ifnStr));
			}
			if (tfnAddr == null && ifnAddr == null) {
				String methodStr = getMethodPrototypeString(method.getName(), methodFuncDef);
				sb.append(!sb.isEmpty() ? "\n" : "").append(methodStr);
			}
		}
		return sb.toString();
	}
	
	public String getMethodPrototypeString(String methodName, GoFuncType funcdefType) {
		return getMethodPrototypeString(getSymbolName().getBaseTypeName(), methodName, funcdefType);
	}

	public String getMethodPrototypeString(String recvStr, String methodName,
			GoFuncType funcdefType) {
		return "func (%s) %s%s".formatted(recvStr, methodName,
			funcdefType != null ? funcdefType.getParamListString() : "(???) ???");
	}

	/**
	 * Returns a descriptive string that defines the declaration of this type.
	 * <p>
	 * This method should be overloaded by more specific types.
	 * 
	 * @return descriptive string
	 * @throws IOException if error reading data
	 */
	protected String getTypeDeclString() throws IOException {
		return "type " + typ.getName() + " " + typ.getKind();
	}

	@Override
	public String toString() {
		try {
			String s = getTypeDeclString();

			String methodListString = getMethodListString();
			if (!methodListString.isEmpty()) {
				s += "\n\n// Methods\n" + methodListString;
			}

			String interfaceString = getImplementsInterfaceString();
			if (!interfaceString.isEmpty()) {
				s += "\n\n// Interfaces implemented\n" + interfaceString;
			}

			return s;
		}
		catch (IOException e) {
			return super.toString();
		}
	}

	/**
	 * Converts a golang RTTI type structure into a Ghidra data type.
	 * <p>
	 * This default implementation just creates an opaque blob of the appropriate size
	 * 
	 * @param goTypes {@link GoTypeManager} 
	 * @return {@link DataType} that represents the golang type
	 * @throws IOException if error getting name of the type
	 */
	public DataType recoverDataType(GoTypeManager goTypes) throws IOException {
		DataType dt = Undefined.getUndefinedDataType((int) typ.getSize());
		return new TypedefDataType(goTypes.getCP(this), goTypes.getTypeName(this), dt,
			goTypes.getDTM());
	}

	/**
	 * Iterates this type, and any types this type refers to, while registering the types with
	 * the {@link GoRttiMapper} context.
	 * <p>
	 * This method should be overloaded by derived type classes to add any additional types 
	 * referenced by the derived type.
	 *  
	 * @param discoveredTypes set of already iterated types
	 * @return boolean boolean flag, if false the type has already been discovered, if true
	 * the type was encountered for the first time 
	 * @throws IOException if error reading type info
	 */
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!discoveredTypes.add(context.getStructureStart())) {
			return false;
		}
		GoUncommonType ut = getUncommonType();
		if (ut != null) {
			for (GoMethod method : ut.getMethods()) {
				GoType methodType = method.getType();
				if (methodType != null) {
					methodType.discoverGoTypes(discoveredTypes);
				}
			}
		}
		return true;
	}

	@Override
	public boolean isValid() {
		return typ.isValid();
	}

}
