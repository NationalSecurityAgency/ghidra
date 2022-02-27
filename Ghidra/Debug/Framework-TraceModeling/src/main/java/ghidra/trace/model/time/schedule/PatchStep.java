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
package ghidra.trace.model.time.schedule;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import javax.help.UnsupportedOperationException;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PatchStep implements Step {
	protected final long threadKey;
	protected final String sleigh;
	protected final int hashCode;

	public static PatchStep parse(long threadKey, String stepSpec) {
		// TODO: Can I parse and validate the sleigh here?
		if (!stepSpec.startsWith("{") || !stepSpec.endsWith("}")) {
			throw new IllegalArgumentException("Cannot parse step: '" + stepSpec + "'");
		}
		return new PatchStep(threadKey, stepSpec.substring(1, stepSpec.length() - 1));
	}

	public PatchStep(long threadKey, String sleigh) {
		this.threadKey = threadKey;
		this.sleigh = Objects.requireNonNull(sleigh);
		this.hashCode = Objects.hash(threadKey, sleigh); // TODO: May become mutable
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof PatchStep)) {
			return false;
		}
		PatchStep that = (PatchStep) obj;
		if (this.threadKey != that.threadKey) {
			return false;
		}
		if (!this.sleigh.equals(that.sleigh)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		if (threadKey == -1) {
			return "{" + sleigh + "}";
		}
		return String.format("t%d-{%s}", threadKey, sleigh);
	}

	@Override
	public int getTypeOrder() {
		// When comparing sequences, those with sleigh steps are ordered after those with ticks
		return 10;
	}

	@Override
	public boolean isNop() {
		// TODO: If parsing beforehand, base on number of ops
		return sleigh.length() == 0;
	}

	@Override
	public long getThreadKey() {
		return threadKey;
	}

	@Override
	public long getTickCount() {
		return 0; // Philosophically correct
	}

	@Override
	public long getPatchCount() {
		return 1;
	}

	@Override
	public boolean isCompatible(Step step) {
		// TODO: Can we combine ops?
		return false; // For now, never combine sleigh steps
	}

	@Override
	public void addTo(Step step) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Step subtract(Step step) {
		if (this.equals(step)) {
			return Step.nop();
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public Step clone() {
		return new PatchStep(threadKey, sleigh);
	}

	@Override
	public long rewind(long count) {
		return count - 1;
	}

	@Override
	public CompareResult compareStep(Step step) {
		CompareResult result;

		result = compareStepType(step);
		if (result != CompareResult.EQUALS) {
			return result;
		}

		PatchStep that = (PatchStep) step;
		result = CompareResult.unrelated(Long.compare(this.threadKey, that.threadKey));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		// TODO: Compare ops, if/when we pre-compile
		result = CompareResult.unrelated(this.sleigh.compareTo(that.sleigh));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		return CompareResult.EQUALS;
	}

	@Override
	public <T> void execute(PcodeThread<T> emuThread, Consumer<PcodeThread<T>> stepAction,
			TaskMonitor monitor) throws CancelledException {
		PcodeProgram prog = emuThread.getMachine().compileSleigh("schedule", List.of(sleigh + ";"));
		emuThread.getExecutor().execute(prog, emuThread.getUseropLibrary());
	}
}
