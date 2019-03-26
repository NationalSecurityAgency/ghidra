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
/*
 * Created on May 23, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.pcode.PcodeOp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * 
 */
public class ConstructorPcodeTemplate implements Serializable {
	private HandleTemplate result;
	private ArrayList<Object> pcodeDirectives;
	private int delaySlotDepth;
	private int flowFlags;
	
	public ConstructorPcodeTemplate() {
		pcodeDirectives = new ArrayList<Object>();
	}

	public void addPcodeOpTemplate(Object opT) throws SledException { 
		if (opT.getClass() == HandleTemplate.class)
			result = (HandleTemplate) opT;
		else {
			if (opT.getClass() == Integer.class) {
				if (delaySlotDepth == 0)
					delaySlotDepth = ((Integer) opT).intValue();
				else throw new SledException("only one delay slot directive is allowed in a constructor");
			}
			pcodeDirectives.add(opT);
		}
	}

	public void trimToSize() { pcodeDirectives.trimToSize();}

	/**
	 * The default pcode generated for a constructor is typically
	 * not very efficient.  For example, for an add instruction,
	 * we might generate something like
	 * 
	 * tmp1 = LOAD register_space register1
	 * tmp2 = LOAD register_space register2
	 * tmp3 = ADD tmp1 tmp2
	 *        STORE register_space register3 tmp3
	 * 
	 * This routine marks opcodes and varnodes as potentially omitable,
	 * which allows us to generate much simpler pcode whenever there
	 * are no dynamic references involved.  In the case above we would
	 * replace the 4 pcode ops above with a single pcode op:
	 * 
	 * register3 = ADD register1 register2
	 */
	public void optimize() {
		int i;
		OpTemplate op;
		VarnodeTemplate vt;
		Operand ref;
		
		flowFlags = 0; // default;
		for (i = 0; i < pcodeDirectives.size(); i++) {
			try {
				op = (OpTemplate) pcodeDirectives.get(i);
			} catch (ClassCastException e) {continue;}
			
			adjustFlowFlags(op);

			if (op.opcode() == PcodeOp.LOAD) {
//				if (op.output().offset().resolve(null,null,0) == 0x4da0) {
//					i = i + 0;
//				}
				if (!op.output().oneuse()) continue; // Only optimize oneuse temp. uniques
				vt = op.input(1);
				if (vt.space().type() != ConstantTemplate.HANDLE) continue;
				if (vt.offset().type() != ConstantTemplate.HANDLE) continue;
				if (vt.size().type() != ConstantTemplate.HANDLE) continue;
				ref = vt.space().operand();
				if (vt.offset().operand() != ref) continue;
				if (vt.size().operand() != ref) continue;
				op.output().setReplace(ref,true);
				op.setOmit(ref);
			}				
			else if (op.opcode() == PcodeOp.STORE){
				if (!op.input(2).oneuse()) continue; // Only optimize oneuse temp. uniques
				if (op.input(2).loadomit()) continue; // Don't omit if storing an omitted load
				vt = op.input(1);
				if (vt.space().type() != ConstantTemplate.HANDLE) continue;
				if (vt.offset().type() != ConstantTemplate.HANDLE) continue;
				if (vt.size().type() != ConstantTemplate.HANDLE) continue;
				ref = vt.space().operand();
				if (vt.offset().operand() != ref) continue;
				if (vt.size().operand() != ref) continue;
				op.input(2).setReplace(ref,false);
				op.setOmit(ref);
			}
		}
	}

	/**
	 * @param op
	 */
	private void adjustFlowFlags(OpTemplate op) throws SledException {

		int destType;

		if ((flowFlags&ConstructorInfo.NO_FALLTHRU)!=0)
			throw new SledException("Template contains dead code");
		switch (op.opcode()) {
		case PcodeOp.BRANCH:
			destType = op.input(0).offset().type();
			if (destType == ConstantTemplate.JUMP_NEXT)
				flowFlags |= ConstructorInfo.BRANCH_TO_END|ConstructorInfo.NO_FALLTHRU;
			else if (destType == ConstantTemplate.JUMP_START)
				flowFlags |= ConstructorInfo.NO_FALLTHRU;
			else
				flowFlags |= ConstructorInfo.JUMPOUT|ConstructorInfo.NO_FALLTHRU;
			break;
		case PcodeOp.BRANCHIND:
			flowFlags |= ConstructorInfo.BRANCH_INDIRECT|ConstructorInfo.NO_FALLTHRU;
			break;
		case PcodeOp.CALL:
			flowFlags |= ConstructorInfo.CALL;
			break;
		case PcodeOp.CALLIND:
			flowFlags |= ConstructorInfo.CALL_INDIRECT;
			break;
		case PcodeOp.CBRANCH:
			destType = op.input(0).offset().type();
			if (destType==ConstantTemplate.JUMP_NEXT)
				flowFlags |= ConstructorInfo.BRANCH_TO_END;
			else if (destType!=ConstantTemplate.JUMP_START)
				flowFlags |= ConstructorInfo.JUMPOUT;
			break;
		case PcodeOp.RETURN:
			flowFlags |= ConstructorInfo.RETURN | ConstructorInfo.NO_FALLTHRU;
			break;
		default: break;
		}
	}

	public int getFlowFlags() { return flowFlags; }

	/**
	 * Method getPcode.  Recursive pcode generation method.
	 * @param pcode - current list of pcode instructions to which we will append new instructions
	 * @param position
	 * @param off
	 * @param delayPcode - pcode for instruction(s) in delay slot
	 * @return HandleTemplate - handle for the result of this constructors pcode
	 */
	public Handle getPcode(ArrayList<PcodeOp> pcode, Position position, int off, ArrayList<PcodeOp> delayPcode) throws Exception {

		int i;
		HashMap<Object, Handle> handles = new HashMap<Object, Handle>();
		
		for (i = 0; i < pcodeDirectives.size(); i++) {
			Object o = pcodeDirectives.get(i);
						
			if (o.getClass() == OpTemplate.class) {
				if (((OpTemplate) o).omit()) continue;
				pcode.add(((OpTemplate) o).getPcode(handles,position,pcode.size(),off));
			}
			else if (o.getClass() == Operand.class) { // must be a "build operand" directive
				Handle ht = ((Operand) o).getHandle(pcode, position,off);
				if (ht != null) handles.put(o,ht);
			}
			else if (o.getClass() == Integer.class) {
				if (delayPcode != null)
					pcode.addAll(delayPcode);
				else
					throw new SledException("delay slot code requested at inappropriate level of constructor tree");
			}
			else
				throw new SledException("Invalid pcode directive");
		}

		if (result == null) return null;
        return result.resolve(handles,position,off);
	}

	public int delaySlotDepth() { return delaySlotDepth; }

	public HandleTemplate result() { return result; }

}
