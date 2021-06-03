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
package ghidra.app.plugin.processors.generic;

import java.io.Serializable;
import java.util.HashMap;

import ghidra.program.model.address.*;
import ghidra.program.model.pcode.Varnode;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * {@literal Window>Preferences>Java>Templates.}
 * To enable and disable the creation of type comments go to
 * {@literal Window>Preferences>Java>Code Generation.}
 */
public class VarnodeTemplate implements Serializable {

	private boolean loadomit;
	private Operand replace;
	private AddressFactory addressFactory;
	
	private int hashCode;

	private ConstantTemplate space;
	private ConstantTemplate offset;
	private ConstantTemplate size;
//	private OpTemplate def; // Defining op (if there is one)	
	private boolean oneuse = false;

	public VarnodeTemplate(
		ConstantTemplate space,
		ConstantTemplate offset,
		ConstantTemplate size,
		AddressFactory addressFactory,
		boolean ou) {

		this.space = space;
		this.offset = offset;
		this.size = size;
		this.addressFactory = addressFactory;
		oneuse = ou;
		hashCode = space.hashCode() + offset.hashCode() + size.hashCode();
		if (oneuse) hashCode += 1;
	}

	/**
	 * Method setDef.
	 * @param opTemplate
	 */
	public void setDef(OpTemplate opTemplate) {
//		def = opTemplate;
	}

	/**
	 * Method resolve.
	 * @param handles
	 * @return Varnode
	 */
	public Varnode resolve(HashMap<Object, Handle> handles, Position position, int bufoff) throws Exception {
		int spaceID,sz;
		long off;

		if (replace != null && !replace.dynamic()) {
			Handle h = replace.getHandle();
			spaceID = (int) h.getLong(Handle.SPACE,0);
			off =           h.getLong(Handle.OFFSET,Handle.OFFSET);
			sz =      (int) h.getLong(Handle.SIZE,0);
		}
		else {
			spaceID = (int) space.resolve(handles, position, bufoff);
			off =          offset.resolve(handles, position, bufoff);
			sz =       (int) size.resolve(handles, position, bufoff);
		}
		Address addr = getMaskedAddr(spaceID, off);
		return new Varnode(addr,sz);
	}

	/**
	 * Resolves a varnode at the given position and buffer offset
	 * @param position the position
	 * @param bufoff the buffer offset
	 * @return the resolved {@link Varnode raw varnode}. (<b>Only</b> contains an address and size)
	 * @throws Exception if an error occurs resolving the varnode
	 */
	public Varnode resolve(Position position, int bufoff) throws Exception {
		int spaceID = (int) space.resolve(position, bufoff);
		long off =          offset.resolve(position, bufoff);
		int sz =       (int) size.resolve(position, bufoff);
		Address addr = getMaskedAddr(spaceID, off);
		return new Varnode(addr,sz);
	}

	private Address getMaskedAddr(int spaceID, long off) {
		AddressSpace mySpace = addressFactory.getAddressSpace(spaceID);
		return mySpace.getTruncatedAddress(off, false);
	}
	
	public boolean oneuse() { return oneuse; }

	public ConstantTemplate space() { return space; }
	public ConstantTemplate offset() { return offset; }
	public ConstantTemplate size() { return size; }

	public void setReplace(Operand op, boolean load) {
		replace = op;
		if (load) loadomit = true;
	}
	
	public boolean loadomit() {	return loadomit; }
	
	@Override
    public int hashCode() {return hashCode; }
	@Override
    public boolean equals(Object o) {
		if (o.getClass() != VarnodeTemplate.class) return false;
		VarnodeTemplate vt = (VarnodeTemplate) o;
		if (vt.hashCode() != hashCode) return false;
		if (!vt.space().equals(this.space)) return false;
		if (!vt.offset().equals(this.offset)) return false;
		if (!vt.size().equals(this.size)) return false;
		return true;
	}


}
