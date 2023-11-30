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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.CancelledException;

/**
 * A {@link GoType} structure that defines a golang interface. 
 */
@StructureMapping(structureName = "runtime.interfacetype")
public class GoInterfaceType extends GoType {

	@FieldMapping
	@MarkupReference("getPkgPath")
	private long pkgpath;	// pointer to name 

	@FieldMapping
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
		mhdr.markupArray(null, getStructureNamespace(), GoIMethod.class, false, session);
		mhdr.markupArrayElements(GoIMethod.class, session);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		DataType dt = programContext.getStructureDataType(GoIface.class);

		String name = getUniqueTypename();
		if (!dt.getName().equals(name)) {
			dt = new TypedefDataType(programContext.getRecoveredTypesCp(getPackagePathString()),
				name, dt, programContext.getDTM());
		}
		return dt;
	}

	@Override
	public String getMethodListString() throws IOException {
		StringBuilder sb = new StringBuilder();
		String ifaceName = getNameWithPackageString();
		for (GoIMethod imethod : getMethods()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			String methodStr = imethod.getName();
			GoType type = imethod.getType();
			if (type instanceof GoFuncType funcType) {
				methodStr = funcType.getFuncPrototypeString(methodStr, ifaceName);
			}
			else {
				methodStr = "func %s()".formatted(methodStr);
			}
			sb.append(methodStr);
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

}
