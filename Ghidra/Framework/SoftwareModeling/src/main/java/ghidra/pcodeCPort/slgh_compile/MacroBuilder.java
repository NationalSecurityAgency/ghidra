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
package ghidra.pcodeCPort.slgh_compile;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.*;
import ghidra.pcodeCPort.semantics.ConstTpl.const_type;
import ghidra.sleigh.grammar.Location;

public class MacroBuilder extends PcodeBuilder {

	private SleighCompile slgh;
	private Location location;
	private boolean haserror = false;
	private VectorSTL<OpTpl> outvec = null;
	private VectorSTL<HandleTpl> params = new VectorSTL<HandleTpl>();

	public MacroBuilder(SleighCompile sl,Location loc,VectorSTL<OpTpl> ovec, int lbcnt) {
		super(lbcnt);
		slgh = sl;
		location = loc;
		outvec = ovec;
	}

	public boolean hasError() {
		return haserror;
	}
	
	@Override
	public void appendBuild(OpTpl bld, int secnum) {
		dump(bld);
	}

	@Override
	public void appendCrossBuild(OpTpl bld, int secnum) {
		dump(bld);
	}

	@Override
	public void delaySlot(OpTpl op) {
		dump(op);
	}

	private void free() {
		IteratorSTL<HandleTpl> iter;
		for (iter = params.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().dispose();
		}

		params.clear();
	}

	// Set up parameters for a particular macro invocation
	public void setMacroOp(OpTpl macroop) {
		free();
		for (int i = 1; i < macroop.numInput(); ++i) {
			VarnodeTpl vn = macroop.getIn(i);
			HandleTpl hand = new HandleTpl(vn);
			params.push_back(hand);
		}
	}

	@Override
	public void dump(OpTpl op) {

		OpTpl clone = new OpTpl(op.location, op.getOpcode());
		VarnodeTpl vn = op.getOut();
		if (vn != null) {
			VarnodeTpl v_clone = new VarnodeTpl(null, vn);
			clone.setOutput(v_clone);
		}
		for (int i = 0; i < op.numInput(); ++i) {
			vn = op.getIn(i);
			VarnodeTpl v_clone = new VarnodeTpl(null, vn);
			if (v_clone.isRelative()) {
				// Adjust relative index, depending on the labelbase
				long val = v_clone.getOffset().getReal() + getLabelBase();
				v_clone.setRelative(val);
			}
			clone.addInput(v_clone);
		}
		if (!transferOp(clone,params))
			clone.dispose();
	}

	// A label within a macro is local to the macro, but when
	// we expand the macro, we have to adjust the index of
	// the label, which is local to the macro, so that it fits
	// in with other labels local to the parent
	@Override
	public void setLabel(OpTpl op) {

		OpTpl clone = new OpTpl(op.location, op.getOpcode());
		VarnodeTpl v_clone = new VarnodeTpl(null, op.getIn(0)); // Clone the label index
		// Make adjustment to macro local value so that it is parent local
		long val = v_clone.getOffset().getReal() + getLabelBase();
		v_clone.setOffset(val);
		clone.addInput(v_clone);
		outvec.push_back(clone);
	}

	private void reportError(String val) {
		slgh.reportError(location, val);
		haserror = true;
	}
	
	private boolean transferOp(OpTpl op,VectorSTL<HandleTpl> params) {
		VarnodeTpl outvn = op.getOut();
		int handleIndex=0;
		int plus;
		boolean hasrealsize = false;
		long realsize = 0;
		
		if (outvn != null) {
			plus = outvn.transfer(params);
			if (plus >= 0) {
				reportError("Cannot currently assign to bitrange of macro parameter that is a temporary");
				return false;
			}
		}
		
		for(int i=0;i<op.numInput();++i) {
			VarnodeTpl vn = op.getIn(i);
			if (vn.getOffset().getType() == const_type.handle) {
				handleIndex = vn.getOffset().getHandleIndex();
				hasrealsize = (vn.getSize().getType()==const_type.real);
				realsize = vn.getSize().getReal();
			}
			plus = vn.transfer(params);
			if (plus >= 0) {
				if (!hasrealsize) {
					reportError("Problem with bit range operator in macro");
					return false;
				}
				long newtemp = slgh.getUniqueAddr();		// Generate a new temporary location
				
				// Generate a SUBPIECE op that implements the offset_plus
				OpTpl subpieceop = new OpTpl(location,OpCode.CPUI_SUBPIECE);
				VarnodeTpl newvn = new VarnodeTpl(location,new ConstTpl(slgh.getUniqueSpace()),
									new ConstTpl(const_type.real,newtemp),
									new ConstTpl(const_type.real,realsize));
				subpieceop.setOutput(newvn);
				HandleTpl hand = params.get(handleIndex);
				VarnodeTpl origvn = new VarnodeTpl(location,hand.getSpace(),hand.getPtrOffset(),hand.getSize());
				subpieceop.addInput(origvn);
				VarnodeTpl plusvn = new VarnodeTpl(location,new ConstTpl(slgh.getConstantSpace()),
													new ConstTpl(const_type.real,plus),
													new ConstTpl(const_type.real,4) );
				subpieceop.addInput(plusvn);
				outvec.push_back(subpieceop);
				vn.dispose();										// Replace original varnode
				op.setInput(new VarnodeTpl(location,newvn),i);		//  with output of subpiece
			}
		}
		outvec.push_back(op);
		return true;
	}
}
