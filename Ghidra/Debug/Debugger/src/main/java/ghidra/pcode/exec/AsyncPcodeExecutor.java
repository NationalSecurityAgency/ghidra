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
package ghidra.pcode.exec;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.async.AsyncUtils;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An executor which can perform (some of) its work asynchronously
 * 
 * <p>
 * Note that a future returned from, e.g., {@link #executeAsync(SleighProgram, SleighUseropLibrary)}
 * may complete before the computation has actually been performed. They complete when all of the
 * operations have been scheduled, and the last future has been written into the state. (This
 * typically happens when any branch conditions have completed). Instead, a caller should read from
 * the async state, which will return a future. The state will ensure that future does not complete
 * until the computation has been performed -- assuming the requested variable actually depends on
 * that computation.
 * 
 * @param <T> the type of values in the state
 */
public class AsyncPcodeExecutor<T> extends PcodeExecutor<CompletableFuture<T>> {
	public AsyncPcodeExecutor(SleighLanguage language,
			PcodeArithmetic<CompletableFuture<T>> arithmetic,
			PcodeExecutorStatePiece<CompletableFuture<T>, CompletableFuture<T>> state) {
		super(language, arithmetic, state);
	}

	public CompletableFuture<Void> stepOpAsync(PcodeOp op, PcodeFrame frame,
			SleighUseropLibrary<CompletableFuture<T>> library) {
		if (op.getOpcode() == PcodeOp.CBRANCH) {
			return executeConditionalBranchAsync(op, frame);
		}
		stepOp(op, frame, library);
		return AsyncUtils.NIL;
	}

	public CompletableFuture<Void> stepAsync(PcodeFrame frame,
			SleighUseropLibrary<CompletableFuture<T>> library) {
		try {
			return stepOpAsync(frame.nextOp(), frame, library);
		}
		catch (PcodeExecutionException e) {
			e.frame = frame;
			return CompletableFuture.failedFuture(e);
		}
		catch (Exception e) {
			return CompletableFuture.failedFuture(
				new PcodeExecutionException("Exception during pcode execution", frame, e));
		}
	}

	public CompletableFuture<Void> executeConditionalBranchAsync(PcodeOp op, PcodeFrame frame) {
		Varnode condVar = op.getInput(1);
		CompletableFuture<T> cond = state.getVar(condVar);
		return cond.thenAccept(c -> {
			if (arithmetic.isTrue(cond)) {
				executeBranch(op, frame);
			}
		});
	}

	public CompletableFuture<Void> executeAsync(PcodeProgram program,
			SleighUseropLibrary<CompletableFuture<T>> library) {
		return executeAsync(program.code, program.useropNames, library);
	}

	protected CompletableFuture<Void> executeAsyncLoop(PcodeFrame frame,
			SleighUseropLibrary<CompletableFuture<T>> library) {
		if (frame.isFinished()) {
			return AsyncUtils.NIL;
		}
		return stepAsync(frame, library)
				.thenComposeAsync(__ -> executeAsyncLoop(frame, library));
	}

	public CompletableFuture<Void> executeAsync(List<PcodeOp> code,
			Map<Integer, String> useropNames, SleighUseropLibrary<CompletableFuture<T>> library) {
		PcodeFrame frame = new PcodeFrame(language, code, useropNames);
		return executeAsyncLoop(frame, library);
	}
}
