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

/**
 * 
 */
public interface OperandValue extends Serializable {

	public int length(MemBuffer buf,int offset) throws Exception;
	public ConstructorInfo getInfo(MemBuffer buf, int offset) throws Exception;
  	public String toString(MemBuffer buf, int offset) throws Exception;

	/**
	 * Method getHandle.
	 * @param pcode
	 * @param position
	 * @param off
	 * @return Handle
	 */
	public Handle getHandle(ArrayList<PcodeOp> pcode, Position position, int off) throws Exception;
	/**
	 * @param position
	 * @param off
	 * @return Handle
	 */
	public Handle getHandle(Position position, int off) throws Exception;
	
	public void getAllHandles(ArrayList<Handle> handles,Position position,int offset) throws Exception;
	
	/**
	 * Construct operand representation as a list of objects
	 * 
	 * @param list the list to fill
	 * @param position the operand position
	 * @param off the offset
	 */
	public void toList(ArrayList<Handle> list, Position position, int off)  throws Exception;
	
	/**
	 * Get the size in bits of the value used in the instruction to create this value.
	 */
	public int getSize();

}
