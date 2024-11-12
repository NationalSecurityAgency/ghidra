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
import java.util.List;
import java.util.Set;

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.app.util.viewer.field.AddressAnnotatedStringHandler;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;

/**
 * A {@link GoType} structure that defines a golang interface. 
 */
@StructureMapping(structureName = {"runtime.interfacetype", "internal/abi.InterfaceType"})
public class GoInterfaceType extends GoType {

	@FieldMapping
	@MarkupReference("getPkgPath")
	private long pkgpath;	// pointer to name 

	@FieldMapping(fieldName = {"mhdr", "Methods"})
	private GoSlice mhdr;

	public GoInterfaceType() {
		// empty
	}

	/**
	 * Returns the package path of this type, referenced via the pkgpath field's markup annotation
	 * 
	 * @return package path {@link GoName}a
	 * @throws IOException if error reading
	 */
	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.getGoName(pkgpath);
	}

	/**
	 * Returns a slice containing the methods of this interface.
	 * 
	 * @return slice containing the methods of this interface
	 */
	public GoSlice getMethodsSlice() {
		return mhdr;
	}

	/**
	 * Returns the methods defined by this interface
	 * @return methods defined by this interface
	 * @throws IOException if error reading data
	 */
	public List<GoIMethod> getMethods() throws IOException {
		return mhdr.readList(GoIMethod.class);
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		super.additionalMarkup(session);
		mhdr.markupArray(getStructureLabel() + "_methods", getStructureNamespace(), GoIMethod.class,
			false, session);
		mhdr.markupArrayElements(GoIMethod.class, session);
	}

	@Override
	public DataType recoverDataType(GoTypeManager goTypes) throws IOException {
		Structure genericIfaceDT = programContext.getStructureDataType(GoIface.class);

		CategoryPath ifaceCP = goTypes.getCP(this);
		String ifaceName = goTypes.getTypeName(this);
		StructureDataType ifaceDT =
			new StructureDataType(ifaceCP, ifaceName, genericIfaceDT.getLength(), goTypes.getDTM());

		ifaceDT.replaceWith(genericIfaceDT);

		goTypes.cacheRecoveredDataType(this, ifaceDT);

		Structure itabStruct = getSpecializedITabStruct(ifaceCP, ifaceName, goTypes);

		int itabComponentOrdinal = 0; // TODO: hacky
		DataTypeComponentImpl genericItabDTC = ifaceDT.getComponent(itabComponentOrdinal);
		ifaceDT.replace(itabComponentOrdinal, goTypes.getDTM().getPointer(itabStruct), -1,
			genericItabDTC.getFieldName(), null);

		return ifaceDT;
	}

	public Structure getSpecializedITabStruct(CategoryPath ifaceCP, String ifaceName,
			GoTypeManager goTypes) throws IOException {
		DataTypeManager dtm = goTypes.getDTM();

		Structure genericItabStruct = goTypes.getGenericITabDT();

		StructureDataType itabStruct = new StructureDataType(ifaceCP, ifaceName + "_itab", 0, dtm);
		itabStruct.replaceWith(genericItabStruct);

		int funDTCOrdinal = 4; // a bit of a hack, could also lookup by name "Fun"
		//DataTypeComponentImpl funDtc = itabStruct.getComponent(funDTCOrdinal);
		itabStruct.delete(funDTCOrdinal);

		CategoryPath funcsCP = ifaceCP.extend(itabStruct.getName() + "_funcs");
		for (GoIMethod imethod : getMethods()) {
			FunctionDefinition methodFuncDef = imethod.getFunctionDefinition(false, goTypes);
			try {
				methodFuncDef.setNameAndCategory(funcsCP, imethod.getName());
				itabStruct.add(dtm.getPointer(methodFuncDef), imethod.getName(), null);
				methodFuncDef
						.setCallingConvention(programContext.getDefaultCallingConventionName());
			}
			catch (InvalidNameException | DuplicateNameException | InvalidInputException e) {
				throw new IOException("Error creating itab for " + ifaceName, e);
			}
		}

		return itabStruct;
	}

	@Override
	public String getMethodListString() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (GoIMethod imethod : getMethods()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			String paramListStr = imethod.getType() instanceof GoFuncType funcdefType
					? funcdefType.getParamListString()
					: "(???)";
			sb.append(imethod.getName()).append(paramListStr);
		}
		return sb.toString();
	}
	
	protected String getTypesThatImplementInterfaceString() {
		StringBuilder sb = new StringBuilder();
		for (GoItab goItab : programContext.getGoTypes().getTypesThatImplementInterface(this)) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			try {
				GoType type = goItab.getType();
				sb.append(AddressAnnotatedStringHandler.createAddressAnnotationString(
					type.getStructureContext().getStructureAddress(),
					type.getFullyQualifiedName()));
				sb.append(AddressAnnotatedStringHandler.createAddressAnnotationString(
					goItab.getStructureContext().getStructureAddress(), "[itab]"));
			}
			catch (IOException e) {
				sb.append("bad type info");
			}
		}
		return sb.toString();
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		for (GoIMethod imethod : getMethods()) {
			GoType type = imethod.getType();
			if (type != null) {
				type.discoverGoTypes(discoveredTypes);
			}
		}
		return true;
	}

	@Override
	public boolean isValid() {
		return super.isValid() && typ.getSize() == programContext.getPtrSize() * 2; // runtime.iface?
	}

	@Override
	public String toString() {
		String s = super.toString();

		String implementations = getTypesThatImplementInterfaceString();
		if (!implementations.isEmpty()) {
			s += "\n\n// Implemented by:\n" + implementations;
		}
		return s;
	}

}
