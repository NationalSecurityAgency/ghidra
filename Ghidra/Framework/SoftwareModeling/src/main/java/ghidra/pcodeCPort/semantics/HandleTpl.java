/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.FixedHandle;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.pcodeCPort.translate.Translate;

import java.io.PrintStream;
import java.util.List;

import org.jdom.Element;

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

	public void fix(FixedHandle hand, ParserWalker walker) {
		if (ptrspace.getType() == ConstTpl.const_type.real) {
			// The export is unstarred, but this doesn't mean the varnode
			// being exported isn't dynamic
			space.fillinSpace(hand, walker);
			hand.size = (int) size.fix(walker);
			ptroffset.fillinOffset(hand, walker);
		}
		else {
			hand.space = space.fixSpace(walker);
			hand.size = (int) size.fix(walker);
			hand.offset_offset = ptroffset.fix(walker);
			hand.offset_space = ptrspace.fixSpace(walker);
			if (hand.offset_space.getType() == spacetype.IPTR_CONSTANT) {
				// Handle could have been dynamic but wasn't
				hand.offset_space = null;
				hand.offset_offset <<= hand.space.getScale();
				hand.offset_offset &= hand.space.getMask();
			}
			else {
				hand.offset_size = (int) ptrsize.fix(walker);
				hand.temp_space = temp_space.fixSpace(walker);
				hand.temp_offset = temp_offset.fix(walker);
			}
		}
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

	public void saveXml(PrintStream s) {
		s.append("<handle_tpl>");
		space.saveXml(s);
		size.saveXml(s);
		ptrspace.saveXml(s);
		ptroffset.saveXml(s);
		ptrsize.saveXml(s);
		temp_space.saveXml(s);
		temp_offset.saveXml(s);
		s.append("</handle_tpl>\n");
	}

	public void restoreXml(Element el, Translate trans) {
		List<?> list = el.getChildren();
		space.restoreXml((Element) list.get(0), trans);
		size.restoreXml((Element) list.get(1), trans);
		ptrspace.restoreXml((Element) list.get(2), trans);
		ptroffset.restoreXml((Element) list.get(3), trans);
		ptrsize.restoreXml((Element) list.get(4), trans);
		temp_space.restoreXml((Element) list.get(5), trans);
		temp_offset.restoreXml((Element) list.get(6), trans);
	}

	public void dispose() {
		// TODO Auto-generated method stub

	}

}
