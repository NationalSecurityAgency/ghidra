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

import java.util.List;
import java.util.Set;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;

@StructureMapping(structureName = "runtime.interfacetype")
public class GoInterfaceType extends GoType {

	@FieldMapping
	@MarkupReference("pkgPath")
	private long pkgpath;	// pointer to name 

	@FieldMapping
	private GoSlice mhdr;

	public GoInterfaceType() {
	}

	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.getGoName(pkgpath);
	}

	public String getPkgPathString() throws IOException {
		GoName n = getPkgPath();
		return n != null ? n.getName() : "";
	}

	public GoSlice getMethodsSlice() {
		return mhdr;
	}

	public List<GoIMethod> getMethods() throws IOException {
		return mhdr.readList(GoIMethod.class);
	}

	@Override
	public void additionalMarkup() throws IOException {
		mhdr.markupArray(null, GoIMethod.class, false);
		mhdr.markupArrayElements(GoIMethod.class);
	}

	@Override
	public DataType recoverDataType() throws IOException {
		DataType dt = programContext.getStructureDataType(GoIface.class);

		String name = typ.getNameString();
		if (!dt.getName().equals(name)) {
			dt = new TypedefDataType(programContext.getRecoveredTypesCp(), name, dt,
				programContext.getDTM());
		}
		return dt;
	}

	@Override
	public String getMethodListString() throws IOException {
		StringBuilder sb = new StringBuilder();
		for (GoIMethod imethod : getMethods()) {
			if (!sb.isEmpty()) {
				sb.append("\n");
			}
			String methodStr = imethod.getNameString();
			GoType type = imethod.getType();
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
