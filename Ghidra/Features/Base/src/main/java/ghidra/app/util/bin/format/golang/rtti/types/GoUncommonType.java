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

import java.io.IOException;

import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.util.Msg;

@StructureMapping(structureName = "runtime.uncommontype")
public class GoUncommonType {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoUncommonType> context;

	@FieldMapping(fieldName = "pkgpath")
	@MarkupReference("pkgPath")
	@EOLComment("packagePathString")
	long pkgpath_nameOff;

	@FieldMapping
	int mcount;

	@FieldMapping
	int xcount;

	@FieldMapping
	long moff;

	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), pkgpath_nameOff);
	}

	public String getPackagePathString() throws IOException {
		GoName pkgPath = getPkgPath();
		return pkgPath != null ? pkgPath.getName() : null;
	}

	public GoSlice getMethodsSlice() {
		return new GoSlice(context.getFieldLocation(moff), mcount, mcount, programContext);
	}

	public List<GoMethod> getMethods() throws IOException {
		GoSlice slice = getMethodsSlice();
		if (!slice.isValid(
			programContext.getStructureMappingInfo(GoMethod.class).getStructureLength())) {
			Msg.warn(this, "Bad uncommon method list: %s".formatted(context.getStructureAddress()));
			return List.of();
		}
		return slice.readList(GoMethod.class);
	}

}
