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
import java.util.Map;
import java.util.Set;

import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;

/**
 * Common abstract base class for GoType classes
 */
@PlateComment()
public abstract class GoType implements StructureMarkup<GoType> {
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

	@FieldMapping
	@Markup
	@FieldOutput
	protected GoBaseType typ;

	protected GoBaseType getBaseType() {
		return typ;
	}

	public String getNameString() throws IOException {
		return typ.getNameString();
	}

	public String getDebugId() {
		return "%s@%s".formatted(
			context.getMappingInfo().getDescription(),
			context.getStructureAddress());
	}

	protected long getOffsetEndOfFullType() {
		return context.getStructureEnd() +
			(typ.hasUncommonType()
					? programContext.getStructureMappingInfo(GoUncommonType.class)
							.getStructureLength()
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
		return typ.hasUncommonType()
				? programContext.readStructure(GoUncommonType.class, context.getStructureEnd())
				: null;
	}

	@Override
	public StructureContext<GoType> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return typ.getNameString();
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException {
		GoUncommonType uncommonType = getUncommonType();
		if (uncommonType != null) {
			GoSlice slice = uncommonType.getMethodsSlice();
			slice.markupArray(getStructureName() + "_methods", GoMethod.class, false, session);
			slice.markupArrayElements(GoMethod.class, session);

			session.labelStructure(uncommonType, typ.getNameString() + "_" +
				programContext.getStructureDataTypeName(GoUncommonType.class));
		}
	}

	public String getMethodListString() throws IOException {
		GoUncommonType uncommonType = getUncommonType();
		if (uncommonType == null || uncommonType.mcount == 0) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (GoMethod method : uncommonType.getMethods()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			String methodStr = method.getNameString();
			GoType type = method.getType();
			if (type instanceof GoFuncType funcType) {
				methodStr = funcType.getFuncPrototypeString(methodStr);
			}
			else {
				methodStr = "func %s()".formatted(methodStr);
			}
			sb.append(methodStr);
		}
		return sb.toString();
	}

	protected String getTypeDeclString() throws IOException {
		String s = "type " + typ.getNameString() + " " + typ.getKind();
		String methodListString = getMethodListString();
		if (!methodListString.isEmpty()) {
			s += "\n// Methods\n" + methodListString;
		}
		return s;
	}

	@Override
	public String toString() {
		try {
			return getTypeDeclString();
		}
		catch (IOException e) {
			return super.toString();
		}
	}

	/**
	 * Converts a golang RTTI type structure into a Ghidra data type.
	 * 
	 * @return {@link DataType} that represents the golang type
	 * @throws IOException if error getting name of the type
	 */
	public DataType recoverDataType() throws IOException {
		DataType dt = Undefined.getUndefinedDataType((int) typ.getSize());
		return new TypedefDataType(programContext.getRecoveredTypesCp(), typ.getNameString(), dt,
			programContext.getDTM());
	}

	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!discoveredTypes.add(context.getStructureStart())) {
			return false;
		}
		GoUncommonType uncommonType = getUncommonType();
		if (uncommonType != null) {
			for (GoMethod method : uncommonType.getMethods()) {
				GoType methodType = method.getType();
				if (methodType != null) {
					methodType.discoverGoTypes(discoveredTypes);
				}
			}
		}
		return true;
	}

}
