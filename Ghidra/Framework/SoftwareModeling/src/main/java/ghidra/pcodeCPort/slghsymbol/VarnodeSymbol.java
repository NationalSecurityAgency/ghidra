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
package ghidra.pcodeCPort.slghsymbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;
import java.util.ArrayList;

// A global varnode
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class VarnodeSymbol extends PatternlessSymbol {

	private VarnodeData fix = new VarnodeData();

	public VarnodeSymbol(Location location) {
		super(location);
	}

	public void markAsContext() {
// note: this value was never read		
//		context_bits = true;
	}

	public VarnodeData getFixedVarnode() {
		return fix;
	}

	@Override
	public int getSize() {
		return fix.size;
	}

	@Override
	public void collectLocalValues(ArrayList<Long> results) {
		if (fix.space.getType() == spacetype.IPTR_INTERNAL) {
			results.add(fix.offset);
		}
	}

	@Override
	public symbol_type getType() {
		return symbol_type.varnode_symbol;
	}

	public VarnodeSymbol(Location location, String nm, AddrSpace base, long offset, int size) {
		super(location, nm);
		int addrSize = base.getAddrSize();
		long maxByteOffset = ((long) base.getWordSize() << (8 * addrSize)) - 1;
		long endOffset = offset + size - 1;
		boolean sizeError = size != 0 && Long.compareUnsigned(offset, endOffset) > 0;
		if (!sizeError && addrSize < 8) {
			sizeError = Long.compareUnsigned(endOffset, maxByteOffset) > 0;
		}
		if (sizeError) {
			throw new SleighError(nm + ":" + size + " @ " + base.getName() + ":" +
				String.format("0x%x", offset) + " extends beyond end of space (max offset is " +
				String.format("0x%x", maxByteOffset) + ")", location);
		}

		fix.space = base;
		fix.offset = offset;
		fix.size = size;
	}

	@Override
	public VarnodeTpl getVarnode() {
		return new VarnodeTpl(location, new ConstTpl(fix.space),
			new ConstTpl(ConstTpl.const_type.real, fix.offset),
			new ConstTpl(ConstTpl.const_type.real, fix.size));
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARNODE_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.writeSpace(ATTRIB_SPACE, fix.space.getIndex(), fix.space.getName());
		encoder.writeUnsignedInteger(ATTRIB_OFF, fix.offset);
		encoder.writeSignedInteger(ATTRIB_SIZE, fix.size);
		encoder.closeElement(ELEM_VARNODE_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException

	{
		encoder.openElement(ELEM_VARNODE_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_VARNODE_SYM_HEAD);
	}

}
