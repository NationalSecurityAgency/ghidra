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

import java.util.Set;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.structmapping.*;

/**
 * Represents the fundamental golang rtti type information.
 * <p>
 * The in-memory instance will typically be part of a specialized type structure, depending
 * on the 'kind' of this type.
 * <p>
 * Additionally, there will be an GoUncommonType structure immediately after this type, if
 * the uncommon bit is set in tflag.
 * <p>
 * <pre>
 * struct specialized_type { basetype_struct; (various_fields)* } struct uncommon; 
 * </pre>
 */
@StructureMapping(structureName = "runtime._type")
public class GoBaseType {

	@ContextField
	private StructureContext<GoBaseType> context;

	@ContextField
	private GoRttiMapper programContext;

	@FieldMapping(signedness = Signedness.Unsigned)
	private long size;

	@FieldMapping
	private long ptrdata;

	@FieldMapping
	@EOLComment("flags")
	private int tflag;

	@FieldMapping
	@EOLComment
	private int kind;

	@FieldMapping
	@MarkupReference("name")
	private long str; // an offset relative to containing moduledata's type base addr

	@FieldMapping
	@MarkupReference
	private long ptrToThis;	// an offset relative to containing moduledata's type base addr

	public long getSize() {
		return size;
	}

	public GoKind getKind() {
		return GoKind.parseByte(kind);
	}

	public Set<GoTypeFlag> getFlags() {
		return GoTypeFlag.parseFlags(tflag);
	}

	public int getTflag() {
		return tflag;
	}

	public boolean hasUncommonType() {
		return GoTypeFlag.Uncommon.isSet(tflag);
	}

	@Markup
	public GoName getName() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), str);
	}

	public String getNameString() throws IOException {
		String s = getName().getName();
		return GoTypeFlag.ExtraStar.isSet(tflag) ? s.substring(1) : s;
	}

	@Markup
	public GoType getPtrToThis() throws IOException {
		return programContext.resolveTypeOff(context.getStructureStart(), ptrToThis);
	}
}
