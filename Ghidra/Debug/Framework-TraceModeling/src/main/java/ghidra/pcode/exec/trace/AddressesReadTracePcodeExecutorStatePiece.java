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
package ghidra.pcode.exec.trace;

import java.util.HashMap;
import java.util.Map;

import javax.help.UnsupportedOperationException;

import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;

/**
 * An auxilliary state piece that reports the (trace) address ranges
 * 
 * <p>
 * Except for unique spaces, sets are ignored, and gets simply echo back the range of addresses of
 * the requested read. In unique spaces, the "addresses read" is treated as the value, so that
 * values transiting unique space can correct have their source address ranges reported. Use this
 * with {@link AddressesReadPcodeArithmetic} to compute the union of these ranges during Sleigh
 * expression evaluation. The ranges are translated from the guest platform, if applicable, to the
 * trace address. In the case of registers, the addresses are also translated to the appropriate
 * overlay space, if applicable.
 */
public class AddressesReadTracePcodeExecutorStatePiece
		extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], AddressSetView, AddressSpace>
		implements TracePcodeExecutorStatePiece<byte[], AddressSetView> {

	protected final PcodeTraceDataAccess data;
	private final Map<Long, AddressSetView> unique = new HashMap<>();

	/**
	 * Construct the state piece
	 * 
	 * @param data the trace data access shim
	 */
	public AddressesReadTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data.getLanguage(), BytesPcodeArithmetic.forLanguage(data.getLanguage()),
			AddressesReadPcodeArithmetic.INSTANCE);
		this.data = data;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make 'addresses read' concrete buffers", purpose);
	}

	@Override
	public PcodeTraceDataAccess getData() {
		return data;
	}

	@Override
	public void writeDown(PcodeTraceDataAccess into) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected AddressSpace getForSpace(AddressSpace space, boolean toWrite) {
		return space;
	}

	@Override
	protected void setInSpace(AddressSpace space, long offset, int size, AddressSetView val) {
		if (!space.isUniqueSpace()) {
			return;
		}
		// TODO: size is not considered
		unique.put(offset, val);
	}

	@Override
	protected AddressSetView getFromSpace(AddressSpace space, long offset, int size,
			Reason reason) {
		if (space.isUniqueSpace()) {
			AddressSetView result = unique.get(offset);
			if (result == null) {
				return new AddressSet();
			}
			return result;
		}
		Address start = data.translate(space.getAddress(offset));
		if (start == null) {
			return new AddressSet();
		}
		try {
			return new AddressSet(new AddressRangeImpl(start, size));
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public void clear() {
		unique.clear();
	}
}
