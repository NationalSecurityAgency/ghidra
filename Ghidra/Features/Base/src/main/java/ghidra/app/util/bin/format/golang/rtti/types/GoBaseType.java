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
import java.util.Set;

import ghidra.app.util.bin.format.golang.rtti.GoName;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.structmapping.*;

/**
 * Represents the fundamental golang rtti type information.
 * <p>
 * The in-memory instance will typically be part of a specialized type structure, depending
 * on the 'kind' of this type.
 * <p>
 * Additionally, there can be an {@link GoUncommonType} structure immediately after this type, if
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
	@MarkupReference("getGoName")
	private long str; // an offset relative to containing moduledata's type base addr

	@FieldMapping
	@MarkupReference
	private long ptrToThis;	// an offset relative to containing moduledata's type base addr

	/**
	 * Returns the size of the type being defined by this structure.
	 * 
	 * @return size of the type being defined
	 */
	public long getSize() {
		return size;
	}

	/**
	 * Returns the {@link GoKind} enum assigned to this type definition.
	 * 
	 * @return {@link GoKind} enum assigned to this type definition
	 */
	public GoKind getKind() {
		return GoKind.parseByte(kind);
	}

	/**
	 * Returns the {@link GoTypeFlag}s assigned to this type definition.
	 * @return {@link GoTypeFlag}s assigned to this type definition
	 */
	public Set<GoTypeFlag> getFlags() {
		return GoTypeFlag.parseFlags(tflag);
	}

	/**
	 * Returns the raw flag value.
	 * 
	 * @return raw flag value
	 */
	public int getTflag() {
		return tflag;
	}

	/**
	 * Returns true if this type definition's flags indicate there is a following GoUncommon
	 * structure.
	 * 
	 * @return true if this type definition's flags indicate there is a following GoUncommon struct
	 */
	public boolean hasUncommonType() {
		return GoTypeFlag.Uncommon.isSet(tflag);
	}

	/**
	 * Returns the name of this type.
	 * 
	 * @return name of this type, as a {@link GoName}
	 * @throws IOException if error reading data
	 */
	@Markup
	public GoName getGoName() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), str);
	}

	/**
	 * Returns the name of this type.
	 * 
	 * @return String name of this type
	 */
	public String getName() {
		String s = programContext.getSafeName(this::getGoName, this, "").getName();
		return GoTypeFlag.ExtraStar.isSet(tflag) && s.startsWith("*") ? s.substring(1) : s;
	}

	/**
	 * Returns a reference to the {@link GoType} that represents a pointer to this type.
	 * 
	 * @return reference to the {@link GoType} that represents a pointer to this type
	 * @throws IOException if error reading
	 */
	@Markup
	public GoType getPtrToThis() throws IOException {
		return programContext.resolveTypeOff(context.getStructureStart(), ptrToThis);
	}
}
