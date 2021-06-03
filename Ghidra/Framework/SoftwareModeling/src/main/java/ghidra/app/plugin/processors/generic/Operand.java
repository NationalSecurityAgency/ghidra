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

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Hashtable;

/**
 * 
 */
public class Operand implements Serializable {
	private boolean dynamic;
	private String name;
	private OperandValue op;
	private Offset offset;
	private Handle handle;
	
//	private int hashCode;
	
	public Operand(String n, OperandValue o, Offset off) {
		name = n;
		op = o;
		offset = off;
//		hashCode = name.hashCode();
	}

	public String toString(MemBuffer buf, int off) throws Exception {
		return op.toString(buf, offset.getOffset(buf,off));
	}

	public int length(MemBuffer buf,int off) throws Exception {
		int o = offset.getOffset(buf,off);
		return op.length(buf,o) + o - off;
	}
	
	public ConstructorInfo getInfo(MemBuffer buf, int off)  throws Exception {
		int o = offset.getOffset(buf,off);
		ConstructorInfo opinfo = op.getInfo(buf,o);
		opinfo.addLength(o-off);
		return opinfo;
	}

	public String name() { return name; }

	public void linkRelativeOffsets(Hashtable<String, Operand> opHash) {
		if (op.getClass() == BinaryExpression.class)
			((BinaryExpression) op).linkRelativeOffsets(opHash);
		else
			offset.setRelativeOffset(opHash);
	}

	/**
	 * Method getHandle.
	 * @param pcode
	 * @param position
	 * @param off
	 * @return Handle
	 */
	public Handle getHandle(ArrayList<PcodeOp> pcode, Position position, int off) throws Exception {

		handle = op.getHandle(pcode,position,offset.getOffset(position.buffer(),off));
		testDynamic();
		return handle;
	}


	/**
	 * Returns previously computed handle for this operand.  Should not
	 * be called before the full version of getHandle, where Position and and
	 * offset are specified.
	 * @return Handle
	 */
	public Handle getHandle() { return handle; }
	
	/**
	 * Returns a handle for this operand *without* generating any pcode
	 * @param position
	 * @param off
	 * @return
	 * @throws Exception
	 */
	public Handle getHandle(Position position, int off) throws Exception {
		return op.getHandle(position,offset.getOffset(position.buffer(),off));
	}

	public void getAllHandles(ArrayList<Handle> handles,Position position,int off) throws Exception {
		op.getAllHandles(handles,position,offset.getOffset(position.buffer(),off));
	}
	
	/**
	 * Method getPcode
	 * @param position
	 * @return array of pcode ops for this operand
	 * @throws Exception
	 */

	public PcodeOp[] getPcode(Position position) throws Exception {
		
		ArrayList<PcodeOp> pcode = new ArrayList<PcodeOp>();
		getHandle(pcode,position,0);
		PcodeOp[] pcodeops = new PcodeOp[pcode.size()];
		pcode.toArray(pcodeops);
		return pcodeops;
	}

	public boolean dynamic() { return dynamic; }
	private void testDynamic() {
		if (handle != null)
			dynamic = handle.dynamic();
		else					// Its possible this param will never be used, so postpone throwing null pointer exception
			dynamic = false;
	}

	/**
	 * @see OperandValue#toList(ArrayList, Position, int)
	 */
	public void toList(ArrayList<Handle> list, Position position, int off) throws Exception {
		op.toList(list, position, offset.getOffset(position.buffer(),off));
	}

	/**
	 * @return
	 */
	public int getSize() {
		return op.getSize();
	}
	
/* 
	public int hashCode() {return hashCode;	}

	public boolean equals(Object o) {
		if (o.getClass() != Operand.class) return false;
		Operand oper = (Operand) o;
		if (oper.hashCode() != hashCode) return false;
		if (!oper.name().equals(name)) return false;
		return true;
	}
*/

}


