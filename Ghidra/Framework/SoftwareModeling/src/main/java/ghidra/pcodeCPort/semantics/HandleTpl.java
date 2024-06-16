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
package ghidra.pcodeCPort.semantics;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.program.model.pcode.Encoder;

public class HandleTpl {

	private ConstTpl space;
	private ConstTpl size;
	private ConstTpl ptrspace;
	private ConstTpl ptroffset;
	private ConstTpl ptrsize;
	private ConstTpl temp_space;
	private ConstTpl temp_offset;

	public ConstTpl getSpace() {
		return space;
	}

	public ConstTpl getPtrSpace() {
		return ptrspace;
	}

	public ConstTpl getPtrOffset() {
		return ptroffset;
	}

	public ConstTpl getPtrSize() {
		return ptrsize;
	}

	public ConstTpl getSize() {
		return size;
	}

	public ConstTpl getTempSpace() {
		return temp_space;
	}

	public ConstTpl getTempOffset() {
		return temp_offset;
	}

	public void setSize(ConstTpl sz) {
		size = new ConstTpl(sz);
	}

	public void setPtrSize(ConstTpl sz) {
		ptrsize = new ConstTpl(sz);
	}

	public void setPtrOffset(long val) {
		ptroffset = new ConstTpl(ConstTpl.const_type.real, val);
	}

	public void setTempOffset(long val) {
		temp_offset = new ConstTpl(ConstTpl.const_type.real, val);
	}

	public HandleTpl() {
		space = new ConstTpl();
		size = new ConstTpl();
		ptrspace = new ConstTpl();
		ptroffset = new ConstTpl();
		ptrsize = new ConstTpl();
		temp_space = new ConstTpl();
		temp_offset = new ConstTpl();
	}

	// Build handle which indicates given varnode
	public HandleTpl(VarnodeTpl vn) {
		space = new ConstTpl(vn.getSpace());
		size = new ConstTpl(vn.getSize());
		ptrspace = new ConstTpl(ConstTpl.const_type.real, 0);
		ptroffset = new ConstTpl(vn.getOffset());
		ptrsize = new ConstTpl();
		temp_space = new ConstTpl();
		temp_offset = new ConstTpl();
	}

	public HandleTpl(ConstTpl spc, ConstTpl sz, VarnodeTpl vn, AddrSpace t_space, long t_offset) {
		space = new ConstTpl(spc);
		size = new ConstTpl(sz);
		ptrspace = new ConstTpl(vn.getSpace());
		ptroffset = new ConstTpl(vn.getOffset());
		ptrsize = new ConstTpl(vn.getSize());
		temp_space = new ConstTpl(t_space);
		temp_offset = new ConstTpl(ConstTpl.const_type.real, t_offset);
		// Build handle to thing being pointed at by -vn-
	}

	public void changeHandleIndex(VectorSTL<Integer> handmap) {
		space.changeHandleIndex(handmap);
		size.changeHandleIndex(handmap);
		ptrspace.changeHandleIndex(handmap);
		ptroffset.changeHandleIndex(handmap);
		ptrsize.changeHandleIndex(handmap);
		temp_space.changeHandleIndex(handmap);
		temp_offset.changeHandleIndex(handmap);
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_HANDLE_TPL);
		space.encode(encoder);
		size.encode(encoder);
		ptrspace.encode(encoder);
		ptroffset.encode(encoder);
		ptrsize.encode(encoder);
		temp_space.encode(encoder);
		temp_offset.encode(encoder);
		encoder.closeElement(ELEM_HANDLE_TPL);
	}

	public void dispose() {
		// TODO Auto-generated method stub

	}

}
