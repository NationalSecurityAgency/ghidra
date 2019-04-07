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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * 
 */
public class Handle implements Serializable {
	public static final int SPACE = 0;
	public static final int OFFSET = 1;
	public static final int SIZE = 2;
	
	private Varnode ptr;
	private int spaceID;
	private int size;

	public Handle(Varnode p, int sp, int sz) {
		ptr = p;
		spaceID = sp;
		size = sz;
	}

	/**
	 * Method getLong.
	 * @param select1
	 * @param select2
	 * @return long
	 */
	public long getLong(int select1, int select2) {
		switch(select1) {
			case SPACE:
				return spaceID;
			case OFFSET: 
				try {
					switch(select2) {
						case SPACE:
							return ptr.getSpace();
						case OFFSET:
							return ptr.getOffset();
						case SIZE:
							return ptr.getSize();
					}
					return 0;		// Should never occur
				}
				catch(Exception e) {
					return 0;		// Should never occur
				}
			case SIZE:
				return size;
			default: 		// Should never occur
				return 0;
		}
	}
	
	public long getSpace() {
		return spaceID;	
	}
	
	public long getSize() {
		return size;
	}
	
	public Varnode getPtr() {
		return ptr;
	}
	
	public boolean isAddress() {
		int spaceType = AddressSpace.ID_TYPE_MASK & spaceID;
		return (spaceType == AddressSpace.TYPE_RAM );
	}
	
	@Deprecated
	public boolean isCodeAddress() {
		throw new UnsupportedOperationException();
	}

	public boolean isDataAddress() {
		int spaceType = AddressSpace.ID_TYPE_MASK & spaceID;
		return spaceType == AddressSpace.TYPE_RAM;
	}

	public boolean isConstant() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_CONSTANT);
	}

	public boolean isRegister() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_REGISTER);
	}

	public boolean isUnique() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_UNIQUE);
	}
	
	public boolean dynamic() {
		return !ptr.isConstant();
	}

}

