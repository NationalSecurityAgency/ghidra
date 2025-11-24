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
package ghidra.pcode.emu.taint.state;

import java.util.*;
import java.util.Map.Entry;

import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.taint.model.TaintSet;
import ghidra.taint.model.TaintVec;
import ghidra.util.MathUtilities;

/**
 * The storage space for taint sets in a single address space (possibly the register space)
 * 
 * <p>
 * This is the actual implementation of the in-memory storage for taint marks. For a stand-alone
 * emulator, this is the full state. For a trace- or Debugger-integrated emulator, this is a cache
 * of taints loaded from a trace backing this emulator. (See {@link TaintPieceHandler}.) Most
 * likely, that trace is the user's current trace.
 */
public class TaintSpace {
	protected final AddressSpace space;
	protected final TaintPcodeExecutorStatePiece piece;
	// TODO: There must be a better way. Similar to SemisparseByteArray?
	protected final NavigableMap<Long, TaintSet> taints = new TreeMap<>(Long::compareUnsigned);
	protected final NavigableMap<Long, PcodeOp> ops = new TreeMap<>(Long::compareUnsigned);

	public TaintSpace(AddressSpace space, TaintPcodeExecutorStatePiece piece) {
		this.space = space;
		this.piece = piece;
	}

	/**
	 * Mark the variable at offset with the given taint sets
	 * 
	 * <p>
	 * This marks possibly several offsets, starting at the given offset. The first taint set in the
	 * vector is used to mark the given offset, then each subsequent set marks each subsequent
	 * offset. This is analogous to the manner in which bytes would be "written" from a source array
	 * into concrete state, starting at a given offset.
	 * 
	 * @param offset the starting offset
	 * @param val the vector of taint sets
	 * @param cb callbacks to receive emulation events
	 */
	public void set(long offset, TaintVec val, PcodeStateCallbacks cb) {
		ops.put(offset, val.getOriginatingOp());
		for (int i = 0; i < val.length; i++) {
			TaintSet s = val.get(i);
			/*
			 * TODO: It'd be nice not to store empties, but then dumping to trace doesn't clear
			 * emptied taints.
			 */
			taints.put(offset + i, s);
		}
		cb.dataWritten(piece, space.getAddress(offset), val.length, val);
	}

	/**
	 * Retrieve the taint sets for the variable at the given offset
	 * 
	 * <p>
	 * This retrieves as many taint sets as there are elements in the given buffer vector. The first
	 * element becomes the taint set at the given offset, then each subsequent element becomes the
	 * taint set at each subsequent offset until the vector is filled. This is analogous to the
	 * manner in which bytes would be "read" from concrete state, starting at a given offset, into a
	 * destination array.
	 * 
	 * @param offset the offset
	 * @param buf the vector to receive taint sets
	 * @param cb callbacks to receive emulation events
	 */
	public void getInto(long offset, TaintVec buf, PcodeStateCallbacks cb) {
		for (int i = 0; i < buf.length; i++) {
			TaintSet s = taints.get(offset + i);
			if (s == null) {
				if (cb.readUninitialized(piece, PcodeStateCallbacks.rngSet(space, offset + i, 1))
						.isEmpty()) {
					s = taints.get(offset + i);
				}
			}
			if (s == null) { // still
				s = TaintSet.EMPTY;
			}
			buf.set(i, s);
		}
	}

	/**
	 * Retrieve the taint sets for the variable at the given offset
	 * 
	 * <p>
	 * This works the same as {@link #getInto(long, TaintVec, PcodeStateCallbacks)}, but creates a
	 * new vector of the given size, reads the taint sets, and returns the vector.
	 * 
	 * @param offset the offset
	 * @param size the size of the variable
	 * @param cb callbacks to receive emulation events
	 * @return the taint vector for that variable
	 */
	public TaintVec get(long offset, int size, PcodeStateCallbacks cb) {
		TaintVec vec = new TaintVec(size);
		getInto(offset, vec, cb);
		return vec;
	}

	public void clear() {
		taints.clear();
	}

	public Map<Register, TaintVec> getRegisterValues(List<Register> registers) {
		Map<Register, TaintVec> result = new HashMap<>();
		for (Register r : registers) {
			long offset = r.getAddress().getOffset();
			TaintVec vec = new TaintVec(r.getNumBytes());
			for (int i = 0; i < vec.length; i++) {
				TaintSet s = taints.get(offset + i);
				if (s == null) {
					continue;
				}
			}
			result.put(r, vec);
		}
		return result;
	}

	public Entry<Long, TaintVec> getNextEntry(long offset) {
		Long check = taints.ceilingKey(offset);
		if (check == null) {
			return null;
		}
		offset = check;
		long end = offset;
		while (taints.get(end) != null) {
			end++;
		}
		PcodeOp pcodeOp = ops.get(offset);  // Needed here to generate the TaintVec
		TaintVec vec = new TaintVec(MathUtilities.unsignedMin(1024, end - offset), pcodeOp);
		getInto(offset, vec, PcodeStateCallbacks.NONE);
		return Map.entry(offset, vec);
	}
}
