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
package ghidra.pcode.emu.taint.plain;

import java.util.HashMap;
import java.util.Map;

import ghidra.pcode.emu.taint.trace.TaintTraceSpace;
import ghidra.taint.model.TaintSet;
import ghidra.taint.model.TaintVec;

/**
 * The storage space for taint sets in a single address space (possibly the register space)
 * 
 * <p>
 * This is the actual implementation of the in-memory storage for taint marks. For a stand-alone
 * emulator, this is the full state. For a trace- or Debugger-integrated emulator, this is a cache
 * of taints loaded from a trace backing this emulator. Most likely, that trace is the user's
 * current trace.
 */
public class TaintSpace {
	// TODO: There must be a better way. Similar to SemisparseByteArray?
	protected final Map<Long, TaintSet> taints = new HashMap<>();

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
	 */
	public void set(long offset, TaintVec val) {
		for (int i = 0; i < val.length; i++) {
			TaintSet s = val.get(i);
			/*
			 * TODO: It'd be nice not to store empties, but then dumping to trace doesn't clear
			 * emptied taints.
			 */
			taints.put(offset + i, s);
		}
	}

	/**
	 * Retrieve the taint sets for the variable at the given offset
	 * 
	 * <p>
	 * This retrieves as many taint sets as there are elements in the given buffer vector. This
	 * first element becomes the taint set at the given offset, then each subsequent element becomes
	 * the taint set at each subsequent offset until the vector is filled. This is analogous to the
	 * manner in which bytes would be "read" from concrete state, starting at a given offset, into a
	 * destination array.
	 * 
	 * @param offset the offset
	 * @param buf the vector to receive taint sets
	 */
	public void getInto(long offset, TaintVec buf) {
		for (int i = 0; i < buf.length; i++) {
			TaintSet s = taints.get(offset + i);
			buf.set(i, s == null ? whenNull(offset + i) : s);
		}
	}

	/**
	 * Retrieve the taint sets for the variable at the given offset
	 * 
	 * <p>
	 * This works the same as {@link #getInto(long, TaintVec)}, but creates a new vector of the
	 * given size, reads the taint sets, and returns the vector.
	 * 
	 * @param offset the offset
	 * @param size the size of the variable
	 * @return the taint vector for that variable
	 */
	public TaintVec get(long offset, int size) {
		TaintVec vec = new TaintVec(size);
		getInto(offset, vec);
		return vec;
	}

	/**
	 * Extension point: Behavior when there is no in-memory taint set at the given offset
	 * 
	 * <p>
	 * This will be overridden by {@link TaintTraceSpace} to implement the lazy loading and
	 * deserialization from a trace.
	 * 
	 * @param offset the offset
	 * @return the taint set to use
	 */
	protected TaintSet whenNull(long offset) {
		return TaintSet.EMPTY;
	}

	public void clear() {
		taints.clear();
	}
}
