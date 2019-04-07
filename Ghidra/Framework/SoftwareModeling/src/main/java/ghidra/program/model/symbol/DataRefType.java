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
package ghidra.program.model.symbol;


/**
 * Class to define reference types for data.
 */
public final class DataRefType extends RefType {
	
	// memory access type
	protected static final int READX    =  1;
	protected static final int WRITEX   =  2;
	protected static final int INDX     =  4;

	private int      access = 0;
	
	/**
	 * Constructs a DataRefType with the given type.
	 */
    protected DataRefType(byte type, String name, int access) {
        super(type, name);
        this.access = access;
	}
	
    @Override
	public boolean isData() {
		return true;
	}
	
	@Override
	public boolean isRead() {
		return (access & READX) == READX;
	}

	@Override	
	public boolean isWrite() {
		return (access & WRITEX) == WRITEX;
	}
	
	@Override
	public boolean isIndirect() {
		return (access & INDX) == INDX;
	}
	
}
