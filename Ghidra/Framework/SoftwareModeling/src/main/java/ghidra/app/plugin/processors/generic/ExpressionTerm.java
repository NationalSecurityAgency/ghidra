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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

import java.io.Serializable;
import java.util.Hashtable;

// TODO needs documentation
/**
 * 
 */
public class ExpressionTerm implements Serializable {
	private ExpressionValue val;
	private Offset offset;
	
	public ExpressionTerm(ExpressionValue v, Offset off) {
		val = v;
		offset = off;
	}

	public long longValue(MemBuffer buf, int off) throws Exception {
		return val.longValue(buf,offset.getOffset(buf,off));
	}

	public int length(MemBuffer buf, int off) throws Exception {
		int o = offset.getOffset(buf,off);
		return o - off + val.length(buf, o);
	}
	

	/**
	 * Method linkRelativeOffsets.
	 * @param opHash
	 */
	public void linkRelativeOffsets(Hashtable<String, Operand> opHash) {
		if (val.getClass() == BinaryExpression.class)
			((BinaryExpression) val).linkRelativeOffsets(opHash);
		else
			offset.setRelativeOffset(opHash);
	}

	public ExpressionValue getValue() { return val; }

	/**
	 * Sets the address space of the expression value
	 * @param space the address space to set
	 */
	public void setSpace(AddressSpace space) throws SledException {
		if (val.getClass() != BinaryExpression.class)
			throw new SledException("Can't add space to an ExpressionTerm that does not contain a BinaryExpression");
		((BinaryExpression) val).setSpace(space);
	}

}
