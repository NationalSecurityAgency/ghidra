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

import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.structmapping.*;

@StructureMapping(structureName = "runtime.imethod")
public class GoIMethod implements StructureMarkup<GoIMethod> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoIMethod> context;

	@FieldMapping
	@MarkupReference
	@EOLComment("nameString")
	private long name;

	@FieldMapping
	@MarkupReference("type")
	private long ityp;

	@Markup
	public GoName getName() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), name);
	}

	public String getNameString() throws IOException {
		GoName n = getName();
		return n != null ? n.getName() : "_blank_";
	}

	@Markup
	public GoType getType() throws IOException {
		return programContext.resolveTypeOff(context.getStructureStart(), ityp);
	}

	@Override
	public StructureContext<GoIMethod> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return getNameString();
	}

}
/*
struct runtime.imethod // Length: 8  Alignment: 4
{ 
  runtime.nameOff  name   
  runtime.typeOff  ityp       
} pack()
*/
