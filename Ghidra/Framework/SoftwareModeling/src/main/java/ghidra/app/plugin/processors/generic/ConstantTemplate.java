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

import ghidra.program.model.address.Address;

/**
 * 
 */
public class ConstantTemplate implements Serializable {
	public static final int REAL = 1;
	public static final int HANDLE = 2;
	public static final int JUMP_START = 3;
	public static final int JUMP_NEXT = 4;
	public static final int JUMP_CODESPACE = 5;

	private int hashCode;

	private int type;
	private Operand op;
	private long realValue;
	private int select1, select2;
	
	public ConstantTemplate(long val) {
		type = REAL;
		realValue = val;
		hashCode = (int) val;
	}
	
	public ConstantTemplate(int t) {
		type = t;
		hashCode = t;
	}
	
	public ConstantTemplate(Operand o, int sel1, int sel2) {
		type = HANDLE;
		op = o;
		select1 = sel1;
		select2 = sel2;
		hashCode = op.hashCode() + select1 + 10*select2;
	}
	

	/**
	 * Constructor ConstantTemplate.
	 * @param o the operand
	 * @param sel1 the first selection
	 */
	public ConstantTemplate(Operand o, int sel1) throws SledException {
		this(o,sel1,0);
		switch(type) {
		case REAL:
		case HANDLE:
		case JUMP_START:
		case JUMP_NEXT:
		case JUMP_CODESPACE:
			break;
		default: throw new SledException("invalid ConstantTemplate type encountered in resolve");
		}
	}



	public int type() {return type;}
	public int select1() {return select1;}
	public int select2() {return select2;}
	
	/**
	 * Method resolve.
	 * @param position the position of the constant to resolve
	 * @param off the offset of the constant
	 * @return long
	 */
	public long resolve(Position position, int off) throws Exception {
		switch(type) {

		case REAL: return realValue;

		case HANDLE: return op.getHandle(position,off).getLong(select1,select2);

		// return the address of the beginning of this instruction.
		case JUMP_START: return position.startAddr().getOffset();
		
		case JUMP_NEXT: return position.nextAddr().getOffset();
		
		case JUMP_CODESPACE:
			Address addr =  position.buffer().getAddress();
				return addr.getAddressSpace().getSpaceID();
		
		default:			// Should never reach here
			return 0;
		}
	}

	/**
	 * @param handles optional map of handles to be used for resolving
	 * @see #resolve(Position, int)
	 * @return long
	 */
	public long resolve(HashMap<Object, Handle> handles, Position position, int off) throws Exception {
		if (type == HANDLE) {
			return handles.get(op).getLong(select1,select2);
		}
        return resolve(position,off);
	}

	public Operand operand() { return op; }
	
	@Override
    public int hashCode() { return hashCode; }
	
	@Override
    public boolean equals(Object o) {
		if (o.getClass() != ConstantTemplate.class) {
			return false;
		}
		ConstantTemplate ct = (ConstantTemplate) o;
		if (ct.hashCode() != hashCode) {
			return false;
		}
		if (ct.type() != type) {
			return false;
		}
		if (type == HANDLE) {
			if (!ct.operand().equals(op)) {
				return false;
			}
			if (ct.select1() != select1) {
				return false;
			}
			if (ct.select2() != select2) {
				return false;
			}
		}

		return true;
	}

}
