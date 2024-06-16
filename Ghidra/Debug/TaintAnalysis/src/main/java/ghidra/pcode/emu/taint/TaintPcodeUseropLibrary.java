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
package ghidra.pcode.emu.taint;

import java.util.Set;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.taint.model.*;
import ghidra.trace.model.time.schedule.TraceSchedule;

/**
 * A userop library for tainting machine state variables
 * 
 * <p>
 * Because Sleigh doesn't allow string literals, we're somewhat limited in what we allow a client to
 * express. We'll allow the generation of taint variables and taint arrays on a 0-up basis, instead
 * of allowing users to "name" the variable. These p-code ops become accessible to scripts, can be
 * used in p-code injects, and can also be used in a {@link TraceSchedule}, i.e., in the "go to
 * time" dialog.
 */
public class TaintPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<Pair<byte[], TaintVec>> {
	private long nextVarId;
	private long nextArrId;

	protected TaintSet nextVar() {
		TaintMark mark = new TaintMark("var_" + nextVarId++, Set.of());
		return TaintSet.of(mark);
	}

	protected String nextArrName() {
		return "arr_" + nextArrId++;
	}

	/**
	 * Taint the given machine variable with a single taint symbol
	 * 
	 * <p>
	 * This generates a single taint symbol (mark), places it in a singleton set, and then broadcast
	 * unions it with the taint vector already on the input variable. For example, assuming an
	 * initial state with no taints, the Sleigh code {@code RAX = taint_var(RAX)} will cause every
	 * byte of RAX to be tainted with "var_0".
	 * 
	 * @param in the input value
	 * @return the same value, with the generated taint unioned in
	 */
	@PcodeUserop
	public Pair<byte[], TaintVec> taint_var(Pair<byte[], TaintVec> in) {
		return Pair.of(in.getLeft(), in.getRight().eachUnion(nextVar()));
	}

	/**
	 * Taint the given machine variable with an array of taint symbols
	 * 
	 * <p>
	 * This generates a 0-up indexed sequence of taint symbols, unioning each with the corresponding
	 * taint set of the input taint vector. For example, assuming an initial state with no taints,
	 * the Sleigh code {@code RAX = taint_arr(RAX)} will cause RAX to be tainted as
	 * [arr_0_0][arr_0_1]...[arr_0_7].
	 * 
	 * @param in
	 * @return
	 */
	@PcodeUserop
	public Pair<byte[], TaintVec> taint_arr(Pair<byte[], TaintVec> in) {
		TaintVec taint = in.getRight();
		taint = taint.zipUnion(TaintVec.array(nextArrName(), 0, taint.length));
		return Pair.of(in.getLeft(), taint);
	}
}
