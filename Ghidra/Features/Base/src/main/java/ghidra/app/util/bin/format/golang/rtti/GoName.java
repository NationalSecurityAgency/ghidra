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
package ghidra.app.util.bin.format.golang.rtti;

import java.util.EnumSet;
import java.util.Set;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.DataType;

/**
 * Represents a golang "name" construct, which isn't represented in go as a normal structure
 * since it is full of variable length and optional fields.
 * <pre>
 * struct {
 * 	byte flag;
 * 	varint strlen;
 * 	char[strlen] chars; 
 * 	(optional: varint tag_strlen; char [tag_strlen];)
 * 	(optional: int32 pkgpath)
 * }
 * </pre>
 * Because this type has variable length fields (@FieldOutput(isVariableLength=true)), there will
 * be unique structure data types produced for each size combination of a GoName structure, and
 * will be named "GoName_N_M", where N and M are the lengths of the variable fields [name, tag] 
 */
@StructureMapping(structureName = "GoName")
public class GoName implements StructureReader<GoName>, StructureMarkup<GoName> {
	public enum Flag {
		EXPORTED(1 << 0),
		HAS_TAG(1 << 1),
		HAS_PKGPATH(1 << 2),
		EMBEDDED(1 << 3);

		private final int flagValue;

		private Flag(int flagValue) {
			this.flagValue = flagValue;
		}

		public boolean isSet(int value) {
			return (value & flagValue) != 0;
		}

		public static Set<Flag> parseFlags(int b) {
			EnumSet<Flag> result = EnumSet.noneOf(Flag.class);
			for (Flag flag : values()) {
				if (flag.isSet(b)) {
					result.add(flag);
				}
			}
			return result;
		}

	}

	@ContextField
	private StructureContext<GoName> context;

	@ContextField
	private GoRttiMapper programContext;

	@FieldOutput(dataTypeName = "byte")
	@EOLComment("flagsSet")
	int flags;

	@FieldOutput(isVariableLength = true)
	@EOLComment("fullNameString")
	GoVarlenString name;

	@FieldOutput(isVariableLength = true)
	GoVarlenString tag;

	@FieldOutput(isVariableLength = true, getter = "pkgPathDataType")
	@MarkupReference("pkgPath")
	long pkgPath;	// uint32, nameoffset, only present if flags.HAS_PKGPATH

	@Override
	public void readStructure() throws IOException {
		flags = context.getReader().readNextUnsignedByte();
		name = programContext.readStructure(GoVarlenString.class, context.getReader());
		tag = Flag.HAS_TAG.isSet(flags)
				? programContext.readStructure(GoVarlenString.class, context.getReader())
				: null;
		pkgPath = Flag.HAS_PKGPATH.isSet(flags)
				? context.getReader().readNextUnsignedInt()
				: 0;
	}

	public String getName() {
		return name.getString();
	}

	public String getTag() {
		return tag != null ? tag.getString() : "";
	}

	@Markup
	public GoName getPkgPath() throws IOException {
		return programContext.resolveNameOff(context.getStructureStart(), pkgPath);
	}

	public DataType getPkgPathDataType() {
		return Flag.HAS_PKGPATH.isSet(flags)
				? programContext.getInt32DT()
				: null;
	}

	public String getFullNameString() throws IOException {
		GoName pkgPathName = getPkgPath();
		return (pkgPathName != null ? pkgPathName.getFullNameString() + "." : "") + getName();
	}

	public int getFlags() {
		return flags;
	}

	public Set<Flag> getFlagsSet() {
		return Flag.parseFlags(flags);
	}

	@Override
	public StructureContext<GoName> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return getName();
	}

}
