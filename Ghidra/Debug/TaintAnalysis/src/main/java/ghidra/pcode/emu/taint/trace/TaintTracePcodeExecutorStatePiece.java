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
package ghidra.pcode.emu.taint.trace;

import ghidra.pcode.emu.taint.AbstractTaintPcodeExecutorStatePiece;
import ghidra.pcode.emu.taint.TaintPcodeArithmetic;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.trace.TracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.AddressSpace;
import ghidra.taint.model.TaintVec;
import ghidra.trace.model.property.TracePropertyMapSpace;

/**
 * The trace-integrated state piece for holding taint marks
 *
 * <p>
 * See {@link AbstractTaintTracePcodeExecutorStatePiece} for framing. We'll store taint sets in the
 * trace's address property map, which is the recommended scheme for auxiliary state.
 */
public class TaintTracePcodeExecutorStatePiece
		extends AbstractTaintPcodeExecutorStatePiece<TaintTraceSpace>
		implements TracePcodeExecutorStatePiece<byte[], TaintVec> {
	public static final String NAME = "Taint";

	protected final PcodeTraceDataAccess data;
	protected final PcodeTracePropertyAccess<String> property;

	/**
	 * Create a state piece
	 * 
	 * @param data the trace-data access shim
	 */
	public TaintTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data.getLanguage(),
			BytesPcodeArithmetic.forLanguage(data.getLanguage()),
			TaintPcodeArithmetic.forLanguage(data.getLanguage()));
		this.data = data;
		this.property = data.getPropertyAccess(NAME, String.class);
	}

	@Override
	public PcodeTraceDataAccess getData() {
		return data;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we create a map that uses {@link TaintTraceSpace}s. The framework provides the concept
	 * of a space map where storage is actually a cache backed by some other object. The backing
	 * object we'll use here is {@link TracePropertyMapSpace}, which is provided by the
	 * TraceModeling module. We'll need a little bit of extra logic for fetching a register space
	 * vs. a plain memory space, but after that, we need not care which address space the backing
	 * object is for.
	 */
	@Override
	protected AbstractSpaceMap<TaintTraceSpace> newSpaceMap() {
		return new CacheingSpaceMap<PcodeTracePropertyAccess<String>, TaintTraceSpace>() {
			@Override
			protected PcodeTracePropertyAccess<String> getBacking(AddressSpace space) {
				return property;
			}

			@Override
			protected TaintTraceSpace newSpace(AddressSpace space,
					PcodeTracePropertyAccess<String> backing) {
				return new TaintTraceSpace(space, property);
			}
		};
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This does the inverse of the lazy loading. Serialize the state and store it back into the
	 * trace. Technically, it could be a different trace, but it must have identically-named
	 * threads.
	 */
	@Override
	public void writeDown(PcodeTraceDataAccess into) {
		PcodeTracePropertyAccess<String> property = into.getPropertyAccess(NAME, String.class);
		for (TaintTraceSpace space : spaceMap.values()) {
			space.writeDown(property);
		}
	}
}
