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
package ghidra.pcode.emu.jit;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece;
import ghidra.pcode.exec.BytesPcodeExecutorStateSpace;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The state piece for {@link JitDefaultBytesPcodeExecutorState}
 * 
 * <p>
 * This provides access to the internals so that translated passages can pre-fetch certain objects
 * to optimize state accesses.
 */
public class JitBytesPcodeExecutorStatePiece
		extends AbstractBytesPcodeExecutorStatePiece<JitBytesPcodeExecutorStateSpace> {

	/**
	 * An object to manage state for a specific {@link AddressSpace}
	 */
	public class JitBytesPcodeExecutorStateSpace extends BytesPcodeExecutorStateSpace<Void> {

		/**
		 * Construct a state space
		 * 
		 * @param language the emulation target language
		 * @param space the address space
		 * @param backing any extra read-through backing (not used)
		 */
		public JitBytesPcodeExecutorStateSpace(Language language, AddressSpace space,
				Void backing) {
			super(language, space, backing);
		}

		/**
		 * Pre-fetch the byte array for the block (page) containing the given offset
		 * 
		 * <p>
		 * A translated passage is likely to call this several times in its constructor to pre-fetch
		 * the byte arrays for variables (ram, register, and unique) that it accesses directly,
		 * i.e., with a fixed offset. The generated code will then access the byte array directly to
		 * read and write the variable values in the emulator's state.
		 * 
		 * @param offset the {@link Address#getOffset() offset} within this address space.
		 * @return the byte array for the containing block
		 */
		public byte[] getDirect(long offset) {
			return bytes.getDirect(offset);
		}

		/**
		 * Read a variable from this (pre-fetched) state space
		 * 
		 * <p>
		 * A translated passage is likely to call
		 * {@link JitBytesPcodeExecutorStatePiece#getForSpace(AddressSpace, boolean)} once or twice
		 * in its constructor to pre-fetch the per-space backing of any indirect memory variables
		 * that it accesses, i.e., variables with a dynamic offset. These are usually required for
		 * {@link PcodeOp#LOAD} and {@link PcodeOp#STORE} ops. The generated code will then invoke
		 * this method (and {@link #write(long, byte[], int, int) write}) passing in the offset to
		 * access variables in the emulator's state at runtime.
		 * 
		 * @param offset the offset (known at runtime)
		 * @param size the size of the variable
		 * @return the value of the variable as a byte array
		 */
		public byte[] read(long offset, int size) {
			return read(offset, size, Reason.EXECUTE_READ);
		}
	}

	/**
	 * A state space map that creates a {@link JitBytesPcodeExecutorStateSpace} for each needed
	 * {@link AddressSpace}
	 */
	class JitBytesSpaceMap extends SimpleSpaceMap<JitBytesPcodeExecutorStateSpace> {
		@Override
		protected JitBytesPcodeExecutorStateSpace newSpace(AddressSpace space) {
			return new JitBytesPcodeExecutorStateSpace(language, space, null);
		}
	}

	/**
	 * Construct a state piece
	 * 
	 * @param language the emulation target language
	 */
	public JitBytesPcodeExecutorStatePiece(Language language) {
		super(language);
	}

	@Override
	protected AbstractSpaceMap<JitBytesPcodeExecutorStateSpace> newSpaceMap() {
		return new JitBytesSpaceMap();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Overridden to grant public access. The JIT-generated constructors will need to invoke this
	 * method.
	 */
	@Override
	public JitBytesPcodeExecutorStateSpace getForSpace(AddressSpace space, boolean toWrite) {
		return super.getForSpace(space, toWrite);
	}
}
