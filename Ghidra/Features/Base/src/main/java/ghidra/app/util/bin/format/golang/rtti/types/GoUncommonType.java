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

import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.util.Msg;

/**
 * Structure found immediately after a {@link GoType} structure, if it has the uncommon flag
 * set.
 */
@StructureMapping(structureName = {"runtime.uncommontype", "internal/abi.UncommonType"})
public class GoUncommonType {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoUncommonType> context;

	@FieldMapping(fieldName = "pkgpath")
	@MarkupReference("getPkgPath")
	@EOLComment("getPackagePathString")
	long pkgpath_nameOff;

	@FieldMapping
	int mcount;

	@FieldMapping
	int xcount;

	@FieldMapping
	long moff;

	/**
	 * Returns the package path of the type.
	 * 
	 * @return package path of the type
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), pkgpath_nameOff);
	}

	/**
	 * Returns the package path of the type.
	 * @return package path of the type, as a string
	 * @throws IOException if error reading data
	 */
	public String getPackagePathString() throws IOException {
		GoName pkgPath = getPkgPath();
		return pkgPath != null ? pkgPath.getName() : "";
	}

	/**
	 * Returns a slice containing the methods defined by the type.
	 * 
	 * @return slice containing the methods defined by the type
	 */
	public GoSlice getMethodsSlice() {
		return new GoSlice(context.getFieldLocation(moff), mcount, mcount, programContext);
	}

	/**
	 * Returns a list of the methods defined by the type.
	 * 
	 * @return list of the methods defined by the type
	 * @throws IOException if error reading data
	 */
	public List<GoMethod> getMethods() throws IOException {
		GoSlice slice = getMethodsSlice();
		if (!slice.isValid(
			programContext.getStructureMappingInfo(GoMethod.class).getStructureLength())) {
			Msg.warn(this, "Bad uncommon method list: %s".formatted(context.getStructureAddress()));
			return List.of();
		}
		return slice.readList(GoMethod.class);
	}

	/**
	 * Returns the location of where this object, and any known associated optional
	 * structures ends.
	 * 
	 * @return index location of end of this type object
	 */
	public long getEndOfTypeInfo() {
		if (mcount == 0) {
			return context.getStructureEnd();
		}
		// calc end of method array manually since getMethodsSlice() is an artificial slice
		long methodArrayStart = context.getFieldLocation(moff);
		return methodArrayStart +
			mcount * programContext.getStructureMappingInfo(GoMethod.class).getStructureLength();
	}

}
