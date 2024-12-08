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
public abstract class GoType implements StructureMarkup<GoType> {
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

	public String getNameWithPackageString() {
		GoSymbolName parsedPackagePath = GoSymbolName.fromPackagePath(getPackagePathString());
		String tpp = Objects.requireNonNullElse(parsedPackagePath.getTruncatedPackagePath(), "");
		return tpp + getName();
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
	public String getStructureName() throws IOException {
		return getNameWithPackageString();
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
			slice.markupArray(getStructureName() + "_methods", getStructureNamespace(),
				GoMethod.class, false, session);
			slice.markupArrayElements(GoMethod.class, session);

			session.labelStructure(ut,
				typ.getName() + "_" +
					programContext.getStructureDataTypeName(GoUncommonType.class),
				getStructureNamespace());
		}
	}

	protected String getImplementsInterfaceString() {
		StringBuilder sb = new StringBuilder();
		for (GoItab goItab : programContext.getInterfacesImplementedByType(this)) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			try {
				sb.append(AddressAnnotatedStringHandler.createAddressAnnotationString(
					goItab.getInterfaceType().getStructureContext().getStructureAddress(),
					goItab.getInterfaceType().getNameWithPackageString()));
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
		String typeName = getName();
		StringBuilder sb = new StringBuilder();
		for (GoMethod method : ut.getMethods()) {
			GoType ptrType = typ.getPtrToThis();
			String tfnStr = makeMethodStr(method.getType(), method.getName(), typeName);
			String ifnStr = ptrType != null
					? makeMethodStr(method.getType(), method.getName(), ptrType.getName())
					: null;
			Address tfnAddr = method.getTfn();
			if (tfnAddr != null) {
				sb.append(!sb.isEmpty() ? "\n" : "")
						.append(AddressAnnotatedStringHandler.createAddressAnnotationString(tfnAddr,
							tfnStr));
			}
			Address ifnAddr = method.getIfn();
			if (ifnAddr != null && ifnStr != null) {
				sb.append(!sb.isEmpty() ? "\n" : "")
						.append(AddressAnnotatedStringHandler.createAddressAnnotationString(ifnAddr,
							ifnStr));
			}
			if (tfnAddr == null && ifnAddr == null) {
				String methodStr = makeMethodStr(method.getType(), method.getName(), typeName);
				sb.append(!sb.isEmpty() ? "\n" : "").append(methodStr);
			}
		}
		return sb.toString();
	}

	private String makeMethodStr(GoType methodFuncType, String methodName,
			String containingTypeName) throws IOException {
		return methodFuncType instanceof GoFuncType funcdefType
				? funcdefType.getFuncPrototypeString(methodName, containingTypeName)
				: "func (%s) %s(???)".formatted(containingTypeName, methodName);
	}

	/**
	 * Return a funcdef signature for a method that is attached to this type.
	 * 
	 * @param method {@link GoMethod}
	 * @param allowPartial boolean flag, if true, allow returning a partially defined signature
	 * when the method's funcdef type is not specified
	 * @return {@link FunctionDefinition} (that contains a receiver parameter), or null if
	 * the method's funcdef type was not specified and allowPartial was not true
	 * @throws IOException if error reading type info
	 */
	public FunctionDefinition getMethodSignature(GoMethod method, boolean allowPartial)
			throws IOException {
		return programContext.getSpecializedMethodSignature(method.getName(),
			method.getType(), programContext.getRecoveredType(this), allowPartial);
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
	 * Returns the name of this type, after being uniqified against all other types defined in the
	 * program.
	 * <p>
	 * See {@link GoRttiMapper#getUniqueGoTypename(GoType)}.
	 *  
	 * @return name of this type
	 */
	public String getUniqueTypename() {
		return programContext.getUniqueGoTypename(this);
	}

	/**
	 * Converts a golang RTTI type structure into a Ghidra data type.
	 * 
	 * @return {@link DataType} that represents the golang type
	 * @throws IOException if error getting name of the type
	 */
	public DataType recoverDataType() throws IOException {
		DataType dt = Undefined.getUndefinedDataType((int) typ.getSize());
		return new TypedefDataType(programContext.getRecoveredTypesCp(getPackagePathString()),
			getUniqueTypename(), dt, programContext.getDTM());
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

}
