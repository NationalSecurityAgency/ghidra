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
package ghidra.pcode.emu.symz3.trace;

import ghidra.pcode.emu.symz3.AbstractSymZ3PcodeExecutorStatePiece;
import ghidra.pcode.emu.symz3.SymZ3PcodeArithmetic;
import ghidra.pcode.exec.trace.TracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;
import ghidra.trace.model.property.TracePropertyMapSpace;

/**
 * An abstract trace-integrated state piece
 *
 * <p>
 * See {@link AbstractSymZ3TracePcodeExecutorStatePiece} for framing. This class must remain
 * abstract since we need to derive the Debugger-integrated state piece from it. Thus it tightens
 * the bound on {@code <S>} and introduces the parameters necessary to source state from a trace.
 * We'll store SymValueZ3s in the trace's address property map, which is the recommended scheme for
 * auxiliary state.
 */
public abstract class AbstractSymZ3TracePcodeExecutorStatePiece
		extends AbstractSymZ3PcodeExecutorStatePiece<SymZ3TraceSpace>
		implements TracePcodeExecutorStatePiece<SymValueZ3, SymValueZ3> {
	public static final String NAME = "SymValueZ3";

	protected final PcodeTraceDataAccess data;
	protected final PcodeTracePropertyAccess<String> property;

	/**
	 * Create a state piece
	 * 
	 * @param data the trace-data access shim
	 */
	public AbstractSymZ3TracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data.getLanguage(),
			SymZ3PcodeArithmetic.forLanguage(data.getLanguage()),
			SymZ3PcodeArithmetic.forLanguage(data.getLanguage()));
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
	 * Here we create a map that uses {@link SymZ3TraceSpace}s. The framework provides the concept
	 * of a space map where storage is actually a cache backed by some other object. The backing
	 * object we'll use here is {@link TracePropertyMapSpace}, which is provided by the
	 * TraceModeling module. We'll need a little bit of extra logic for fetching a register space
	 * vs. a plain memory space, but after that, we need not care which address space the backing
	 * object is for.
	 */
	@Override
	protected AbstractSpaceMap<SymZ3TraceSpace> newSpaceMap(Language language) {
		return new CacheingSpaceMap<PcodeTracePropertyAccess<String>, SymZ3TraceSpace>() {
			@Override
			protected PcodeTracePropertyAccess<String> getBacking(AddressSpace space) {
				return property;
			}

			@Override
			protected SymZ3TraceSpace newSpace(AddressSpace space,
					PcodeTracePropertyAccess<String> backing) {

				if (space.isConstantSpace()) {
					throw new AssertionError(
						"request for a trace constant space needs to be implemented");
					//return new SymZ3TraceConstantSpace(backing, snap);
				}
				else if (space.isRegisterSpace()) {
					return new SymZ3TraceRegisterSpace(space, backing);
				}
				else if (space.isUniqueSpace()) {
					return new SymZ3TraceUniqueSpace(space, backing);
				}
				else if (space.isLoadedMemorySpace()) {
					return new SymZ3TraceMemorySpace(space, backing);

				}
				else {
					throw new AssertionError("not yet supported space: " + space.toString());
				}

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
		PcodeTracePropertyAccess<String> intoProp = into.getPropertyAccess(NAME, String.class);
		for (SymZ3TraceSpace space : spaceMap.values()) {
			space.writeDown(intoProp);
		}
	}
}
