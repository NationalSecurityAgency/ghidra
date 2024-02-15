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

/**
 * Structure used to define a field in a {@link GoStructType struct type}.
 */
@StructureMapping(structureName = {"runtime.structfield", "internal/abi.StructField"})
public class GoStructField {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoStructField> context;

	@FieldMapping
	@MarkupReference("getGoName")
	@EOLComment("getName")
	private long name;	// direct ptr to GoName

	@FieldMapping
	@MarkupReference("getType")
	private long typ;	// direct ptr to GoType

	@FieldMapping(optional = true) //<=1.18
	private long offsetAnon;	// offsetAnon >> 1 == actual offset, bit 0 = embedded flag

	@FieldMapping(optional = true) //>=1.19 
	private long offset;

	/**
	 * Returns the name of this field.
	 * 
	 * @return name of this field as it's raw GoName value
	 * @throws IOException if error reading
	 */
	@Markup
	public GoName getGoName() throws IOException {
		return name != 0
				? context.getDataTypeMapper().readStructure(GoName.class, name)
				: null;
	}

	/**
	 * Returns the type of this field.
	 * 
	 * @return type of this field
	 * @throws IOException if error reading
	 */
	@Markup
	public GoType getType() throws IOException {
		return programContext.getGoType(typ);
	}

	/**
	 * Setter called by offsetAnon field's serialization, referred by fieldmapping annotation.
	 * 
	 * @param offsetAnon value
	 */
	public void setOffsetAnon(long offsetAnon) {
		this.offsetAnon = offsetAnon;
		this.offset = offsetAnon >> 1;
	}

	/**
	 * Returns the offset of this field.
	 * @return offset of this field
	 */
	public long getOffset() {
		return offset;
	}

//	public boolean isEmbedded() {
//		return (offsetAnon & 0x1) != 0;
//	}

	/**
	 * Returns the name of this field.
	 * 
	 * @return name of this field
	 */
	public String getName() {
		return programContext.getSafeName(this::getGoName, this, null).getName();
	}
}
/*
 
struct runtime.structfield  
   Length: 24  Alignment: 8
{ 
     runtime.name        name            
     runtime._type *  typ                
     uintptr                offsetAnon ---- name changed to offset in next golang ver   
} pack()
*/
