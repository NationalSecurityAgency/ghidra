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
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.mem.MemBuffer;

import java.io.Serializable;
import java.util.Hashtable;

/**
 * 
 */
public class Offset implements Serializable {
	private int offset;
	private Operand relTo;
	private String relToName;

	public Offset(int off, String name) throws SledException {
		if ((off % 8) != 0) throw new SledException("offset must be a multiple of eight bits");
		offset = off/8;
		if (name == null || name.length() == 0) relToName = "";
		else relToName = name;
	}

	public Offset(int off, Operand rel) {
		this(off,rel.name());
		relTo = rel;
	}
	
	/**
	 * Method setRelativeOffset.
	 * @param opHash
	 */
	public void setRelativeOffset(Hashtable<String, Operand> opHash) throws SledException {
		if (relToName != null && relToName.length() != 0) {
			relTo = opHash.get(relToName);
			if (relTo == null) throw new SledException("unable to find relative operand");
		}
	}

	/**
	 * Method getOffset.
	 * @param buf - a MemBuffer of bytes to parse
	 * @param off - offset into the MemBuffer at which to start
	 * @return int - offset into the MemBuffer to which this Offset object points
	 * 						given the bytes in the MemBuffer.
	 */
	public int getOffset(MemBuffer buf, int off) throws Exception {
		int o = off + offset;  // usually we just add the offset to the incoming off.
		
		// but if this Offset is relative to an Operand, then we have to add the
		// length of that operand.
		if (relTo != null) o += relTo.length(buf, off);

		return o;
	}


}
