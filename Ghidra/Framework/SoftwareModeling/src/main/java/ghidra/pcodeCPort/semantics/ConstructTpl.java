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

import java.io.PrintStream;
import java.util.*;

import org.jdom.Element;

import generic.stl.*;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;
import ghidra.sleigh.grammar.LocationUtil;

public class ConstructTpl {
	public final Location loc;
	protected int delayslot;
	protected int numlabels; // Number of label templates
	protected VectorSTL<OpTpl> vec = new VectorSTL<OpTpl>();
	protected HandleTpl result;

	public ConstructTpl(Location loc) {
		this.loc = loc;
		delayslot = 0;
		numlabels = 0;
		result = null;
	}

	public int delaySlot() {
		return delayslot;
	}

	public int numLabels() {
		return numlabels;
	}
	
	public void setNumLabels(int val) {
		numlabels = val;
	}

	public void setOpvec(VectorSTL<OpTpl> opvec) {
		vec = opvec;
	}
	
	public VectorSTL<OpTpl> getOpvec() {
		return vec;
	}

	public HandleTpl getResult() {
		return result;
	}

	public void setResult(HandleTpl t) {
		result = t;
	}

	// Constructor owns its ops and handles
	public void dispose() {
		IteratorSTL<OpTpl> oiter;
		for (oiter = vec.begin(); !oiter.isEnd(); oiter.increment()) {
			oiter.get().dispose();
		}
		if (result != null) {
			// result.dispose();
		}
	}

	public boolean addOp(OpTpl ot) {
		if (ot.getOpcode() == OpCode.CPUI_INDIRECT) {
			if (delayslot != 0) {
				return false; // Cannot have multiple delay slots
			}
			delayslot = (int) ot.getIn(0).getOffset().getReal();
		}
		else if (ot.getOpcode() == OpCode.CPUI_PTRADD) {
			numlabels += 1; // Count labels
		}
		vec.push_back(ot);
		return true;
	}

	public boolean addOpList(VectorSTL<OpTpl> oplist) {
		for (int i = 0; i < oplist.size(); ++i) {
			if (!addOp(oplist.get(i))) {
				return false;
			}
		}
		return true;
	}

	public Pair<Integer, Location> fillinBuild(VectorSTL<Integer> check, AddrSpace const_space) {
		// Make sure there is a build statement for all subtable params
		// Return 0 upon success, 1 if there is a duplicate BUILD, 2 if there is
		// a build for a non-subtable
		OpTpl op;
		VarnodeTpl indvn;
		IteratorSTL<OpTpl> iter;
		ArrayList<Location> locations = new ArrayList<Location>();
		for (iter = vec.begin(); !iter.isEnd(); iter.increment()) {
			op = iter.get();
			locations.add(op.location);
			if (op.getOpcode() == OpCode.CPUI_MULTIEQUAL) { // was BUILD
				int index = (int) op.getIn(0).getOffset().getReal();
				if (check.get(index) != 0) {
					return new Pair<Integer, Location>(check.get(index), op.location);
				}
				check.set(index, 1);
			}
		}
		Location min = LocationUtil.minimum(locations);
		for (int i = 0; i < check.size(); ++i) {
			if (check.get(i) == 0) { // Didn't see a BUILD statement
				op = new OpTpl(min, OpCode.CPUI_MULTIEQUAL);
				indvn =
					new VarnodeTpl(min, new ConstTpl(const_space), new ConstTpl(
						ConstTpl.const_type.real, i), new ConstTpl(ConstTpl.const_type.real, 4));
				op.addInput(indvn);
				vec.insert(vec.begin(), op);
			}
		}
		return new Pair<Integer, Location>(0, null);
	}

	public boolean buildOnly() {
		for (OpTpl op : vec) {
			if (op.getOpcode() != OpCode.CPUI_MULTIEQUAL) {
				return false;
			}
		}
		return true;
	}

	public void changeHandleIndex(VectorSTL<Integer> handmap) {
		IteratorSTL<OpTpl> iter;
		for (iter = vec.begin(); !iter.isEnd(); iter.increment()) {
			OpTpl op = iter.get();
			if (op.getOpcode() == OpCode.CPUI_MULTIEQUAL) {
				int index = (int) op.getIn(0).getOffset().getReal();
				index = handmap.get(index);
				op.getIn(0).setOffset(index);
			}
			else {
				op.changeHandleIndex(handmap);
			}
		}
		if (result != null) {
			result.changeHandleIndex(handmap);
		}
	}

	// set the VarnodeTpl input for a particular op
	// for use with optimization routines
	public void setInput(VarnodeTpl vn, int index, int slot) {
		OpTpl op = vec.get(index);
		VarnodeTpl oldvn = op.getIn(slot);
		op.setInput(vn, slot);
		if (oldvn != null) {
			oldvn.dispose();
		}
	}

	// set the VarnodeTpl output for a particular op
	// for use with optimization routines
	public void setOutput(VarnodeTpl vn, int index) {
		OpTpl op = vec.get(index);
		VarnodeTpl oldvn = op.getOut();
		op.setOutput(vn);
		if (oldvn != null) {
			oldvn.dispose();
		}
	}

	// delete a particular set of ops
	public void deleteOps(VectorSTL<Integer> indices) {
		for (int i = 0; i < indices.size(); ++i) {
			vec.get(indices.get(i));
			vec.set(indices.get(i), null);
		}
		int poscur = 0;
		for (int i = 0; i < vec.size(); ++i) {
			OpTpl op = vec.get(i);
			if (op != null) {
				vec.set(poscur, op);
				poscur += 1;
			}
		}
		while (vec.size() > poscur) {
			vec.pop_back();
		}
	}

	public void saveXml(PrintStream s, int sectionid) {
		s.append("<construct_tpl");
		if (sectionid >= 0) {
			s.append(" section=\"");
			s.print(sectionid);
			s.append("\"");
		}
		if (delayslot != 0) {
			s.append(" delay=\"");
			s.print(delayslot);
			s.append("\"");
		}
		if (numlabels != 0) {
			s.append(" labels=\"");
			s.print(numlabels);
			s.append("\"");
		}
		s.append(">\n");
		if (result != null) {
			result.saveXml(s);
		}
		else {
			s.append("<null/>");
		}
		for (int i = 0; i < vec.size(); ++i) {
			vec.get(i).saveXml(s);
		}
		s.append("</construct_tpl>\n");
	}

	public int restoreXml(Element el, Translate trans) {
		int sectionid = -1;
		String str = el.getAttributeValue("delay");
		if (str != null) {
			delayslot = XmlUtils.decodeUnknownInt(str);
		}
		str = el.getAttributeValue("labels");
		if (str != null) {
			numlabels = XmlUtils.decodeUnknownInt(str);
		}
		str = el.getAttributeValue("section");
		if (str != null) {
			sectionid = XmlUtils.decodeUnknownInt(str);
		}
		List<?> list = el.getChildren();
		Iterator<?> it = list.iterator();
		Element child = (Element) it.next();
		if (child.getName().equals("null")) {
			result = null;
		}
		else {
			result = new HandleTpl();
			result.restoreXml(child, trans);
		}
		while (it.hasNext()) {
			child = (Element) it.next();
			OpTpl op = new OpTpl(null);
			op.restoreXml(child, trans);
			vec.push_back(op);
		}
		return sectionid;
	}

}
