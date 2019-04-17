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
/*
 * Created on Jan 26, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * 
 *
 * The resulting data for a HandleTemplate after all the
 * placeholders have been resolved through context
 */
public class FixedHandle {
	
	//
	// Dynamic Case: *[space]:size offset
	//               load/store offset specified by fields: offset_space, offset_offset, offset_size
	//               load/store space-id corresponds to space field
	//               load/store temp (associated with related loads/stores specified by fields: temp_space, temp_offset, size
	//
	//               constant address location identified by fields: space, size, offset_offset; when offset_space=constant
	//
	// Static Case (memory, register, constant or unique space:
	//               offset_space = null
	//               varnode specified by fields: space, size, offset_offset
	// 
	
	public AddressSpace space;
	public int size;
	public AddressSpace offset_space;
	public long offset_offset;
	public int offset_size;
	public AddressSpace temp_space;
	public long temp_offset;
	
	public boolean fixable = true;
	
	public boolean isInvalid() { 
		return space == null; 
	}
	
	public void setInvalid() { 
		space = null; 
	}
	
	public boolean isDynamic() {
		return offset_space != null;
	}
	
	public Varnode getDynamicOffset() {
		if (space == null || offset_space == null) {
			return null;
		}
		return new Varnode(offset_space.getAddress(offset_offset), offset_size);
	}
	
	public Varnode getDynamicTemp() {
		if (space == null || offset_space == null) {
			return null;
		}
		return new Varnode(temp_space.getAddress(temp_offset), size);
	}
	
	public Varnode getStaticVarnode() {
		if (space == null) {
			return null;
		}
		if (offset_space != null && offset_space.getType() != AddressSpace.TYPE_CONSTANT) {
			return null;
		}
		return new Varnode(space.getAddress(offset_offset), size);
	}
	
	@Override
	public int hashCode() {
		return (int) (offset_offset ^ (offset_offset >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof FixedHandle)) {
			return false;
		}
		FixedHandle other = (FixedHandle)obj;
		return other.space == space &&
			other.size == size &&
			other.offset_space == offset_space &&
			other.offset_offset == offset_offset &&
			other.offset_size == offset_size &&
			other.temp_space == temp_space &&
			other.temp_offset == temp_offset;
	}
	
	
	
	

	

}
