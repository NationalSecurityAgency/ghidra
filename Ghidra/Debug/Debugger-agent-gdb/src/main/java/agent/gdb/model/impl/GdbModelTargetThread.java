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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbManager.ExecSuffix;
import agent.gdb.manager.impl.GdbFrameInfo;
import agent.gdb.manager.impl.GdbThreadInfo;
import agent.gdb.manager.reason.GdbBreakpointHitReason;
import agent.gdb.manager.reason.GdbReason;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(name = "Thread", elements = {
	@TargetElementType(type = Void.class)
}, attributes = {
	@TargetAttributeType(type = Void.class)
})
public class GdbModelTargetThread
		extends DefaultTargetObject<TargetObject, GdbModelTargetThreadContainer> implements
		TargetThread<GdbModelTargetThread>, TargetExecutionStateful<GdbModelTargetThread>,
		TargetSteppable<GdbModelTargetThread>, GdbModelSelectableObject {
	protected static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, TargetStepKind.FINISH, TargetStepKind.LINE, TargetStepKind.OVER,
		TargetStepKind.OVER_LINE, TargetStepKind.RETURN, TargetStepKind.UNTIL);

	protected static String indexThread(int threadId) {
		return PathUtils.makeIndex(threadId);
	}

	protected static String indexThread(GdbThread thread) {
		return indexThread(thread.getId());
	}

	protected static String keyThread(GdbThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final GdbModelImpl impl;
	protected final GdbThread thread;
	private GdbInferior inferior;
	protected String display;
	protected String shortDisplay;
	protected GdbThreadInfo info;

	protected final GdbModelTargetStack stack;

	public GdbModelTargetThread(GdbModelTargetThreadContainer threads,
			GdbModelTargetInferior inferior, GdbThread thread) {
		super(threads.impl, threads, keyThread(thread), "Thread");
		this.impl = threads.impl;
		this.inferior = inferior.inferior;
		this.thread = thread;

		this.stack = new GdbModelTargetStack(this, inferior);

		changeAttributes(List.of(),
			List.of(
				stack),
			Map.of(
				STATE_ATTRIBUTE_NAME, convertState(thread.getState()),
				SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS,
				DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(),
				UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED,
				stack.getName(), stack),
			"Initialized");

		updateInfo().exceptionally(ex -> {
			Msg.error(this, "Could not initialize thread info");
			return null;
		});
	}

	@TargetAttributeType(name = GdbModelTargetStack.NAME, required = true, fixed = true)
	public GdbModelTargetStack getStack() {
		return stack;
	}

	private CompletableFuture<Void> updateInfo() {
		return thread.getInfo().thenAccept(res -> {
			this.info = res;
			changeAttributes(List.of(), Map.of( //
				SHORT_DISPLAY_ATTRIBUTE_NAME, shortDisplay = computeShortDisplay(), //
				DISPLAY_ATTRIBUTE_NAME, display = computeDisplay() //
			), "Initialized");
			listeners.fire.displayChanged(this, getDisplay());
		});
	}

	protected String computeDisplay() {
		StringBuilder sb = new StringBuilder();
		if (info != null) {
			sb.append(shortDisplay);
			sb.append(" ");
			//sb.append(info.getTargetId());
			//sb.append(" ");
			sb.append(info.getInferiorName());
			sb.append(" ");
			sb.append(info.getState());
			sb.append(" ");
			List<GdbFrameInfo> frames = info.getFrames();
			if (!frames.isEmpty()) {
				GdbFrameInfo frame = frames.get(0);
				sb.append("at 0x");
				sb.append(frame.getAddr());
				sb.append(" in ");
				sb.append(frame.getFunc());
			}
			return sb.toString();
		}
		sb.append(thread.getId());
		sb.append(" ");
		sb.append(stack.inferior.inferior.getDescriptor());
		sb.append(" ");
		sb.append(stack.inferior.inferior.getExecutable());
		GdbModelTargetStackFrame top = stack.framesByLevel.get(0);
		if (top == null) {
			return sb.toString();
		}
		sb.append(" 0x");
		sb.append(top.frame.getAddress().toString(16));
		sb.append(" in ");
		sb.append(top.frame.getFunction());
		sb.append(" ()");
		return sb.toString();
	}

	protected String computeShortDisplay() {
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		sb.append(inferior.getId());
		sb.append(".");
		sb.append(info.getId());
		if (info.getTid() != null) {
			sb.append(":");
			sb.append(info.getTid());
		}
		sb.append("]");
		return sb.toString();
	}

	protected TargetExecutionState convertState(GdbState state) {
		switch (state) {
			case RUNNING:
				return TargetExecutionState.RUNNING;
			case STOPPED:
			default:
				return TargetExecutionState.STOPPED;
		}
	}

	protected void threadStateChanged(GdbState state, GdbReason reason) {
		if (state == GdbState.STOPPED) {
			updateStack(); // NB: Callee handles errors
		}
		TargetExecutionState targetState = convertState(state);
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState //
		), reason.desc());
		listeners.fire(TargetExecutionStateListener.class).executionStateChanged(this, targetState);

		if (reason instanceof GdbBreakpointHitReason) {
			GdbBreakpointHitReason bpHit = (GdbBreakpointHitReason) reason;
			GdbStackFrame frame = bpHit.getFrame(thread);
			GdbModelTargetStackFrame f = stack.getTargetFrame(frame);
			long bpId = bpHit.getBreakpointId();
			impl.session.breakpoints.breakpointHit(bpId, f);
		}
	}

	protected ExecSuffix convertToGdb(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return ExecSuffix.FINISH;
			case INTO:
				return ExecSuffix.STEP_INSTRUCTION;
			case LINE:
				return ExecSuffix.STEP;
			case OVER:
				return ExecSuffix.NEXT_INSTRUCTION;
			case OVER_LINE:
				return ExecSuffix.NEXT;
			case RETURN:
				return ExecSuffix.RETURN;
			case UNTIL:
				return ExecSuffix.UNTIL;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in GDB/MI?
				// TODO: This doesn't work, since advance requires a parameter
				return thread.console("advance");
			default:
				return thread.step(convertToGdb(kind));
		}
	}

	protected void invalidateRegisterCaches() {
		stack.invalidateRegisterCaches();
	}

	protected CompletableFuture<?> updateStack() {
		Msg.debug(this, "Updating stack for " + this);
		return stack.update().thenCompose(__ -> updateInfo()).exceptionally(ex -> {
			Msg.error(this, "Could not update stack for thread " + this, ex);
			return null;
		});
	}

	@Override
	@Internal
	public CompletableFuture<Void> select() {
		return thread.select();
	}
}
