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
import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.impl.GdbFrameInfo;
import agent.gdb.manager.impl.GdbThreadInfo;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import agent.gdb.manager.reason.GdbBreakpointHitReason;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "Thread",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetThread
		extends DefaultTargetObject<TargetObject, GdbModelTargetThreadContainer> implements
		TargetThread, TargetExecutionStateful, TargetSteppable, GdbModelSelectableObject {
	protected static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);

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
	protected TargetExecutionState state = TargetExecutionState.INACTIVE;
	private Integer base = 10;

	protected final GdbModelTargetStack stack;

	public GdbModelTargetThread(GdbModelTargetThreadContainer threads,
			GdbModelTargetInferior inferior, GdbThread thread) {
		super(threads.impl, threads, keyThread(thread), "Thread");
		this.impl = threads.impl;
		this.inferior = inferior.inferior;
		this.thread = thread;
		impl.addModelObject(thread, this);

		this.stack = new GdbModelTargetStack(this, inferior);

		changeAttributes(List.of(), List.of(stack), Map.of( //
			STATE_ATTRIBUTE_NAME, state = convertState(thread.getState()), //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SHORT_DISPLAY_ATTRIBUTE_NAME, shortDisplay = computeShortDisplay(), //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay() //
		), "Initialized");

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
		});
	}

	protected String computeDisplay() {
		StringBuilder sb = new StringBuilder();
		sb.append(shortDisplay);
		if (info != null) {
			sb.append(" ");
			sb.append(info.getInferiorName());
			sb.append(" ");
			sb.append(state.name().toLowerCase());
			sb.append(" ");
			List<GdbFrameInfo> frames = info.getFrames();
			if (!frames.isEmpty()) {
				GdbFrameInfo frame = frames.get(0);
				sb.append("at 0x");
				sb.append(frame.getAddr());
				sb.append(" in ");
				sb.append(frame.getFunc());
			}
		}
		else {
			sb.append(" ");
			String executableName = stack.inferior.inferior.getExecutable();
			if (executableName != null) {
				sb.append(executableName);
			}
			GdbModelTargetStackFrame top = stack.framesByLevel.get(0);
			if (top == null) {
				return sb.toString();
			}
			sb.append(" 0x");
			sb.append(top.frame.getAddress().toString(16));
			sb.append(" in ");
			sb.append(top.frame.getFunction());
			sb.append(" ()");
		}
		return sb.toString();
	}

	protected String computeShortDisplay() {
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		sb.append(inferior.getId());
		sb.append(".");
		if (info == null) {
			sb.append(thread.getId());
		}
		else {
			sb.append(info.getId());
			Integer tid = info.getTid();
			if (tid != null) {
				String tidstr = Integer.toString(tid, base);
				if (base == 16) {
					tidstr = "0x" + tidstr;
				}
				sb.append(":");
				sb.append(tidstr);
			}
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

	protected StepCmd convertToGdb(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return StepCmd.FINISH;
			case INTO:
				return StepCmd.STEPI;
			case LINE:
				return StepCmd.STEP;
			case OVER:
				return StepCmd.NEXTI;
			case OVER_LINE:
				return StepCmd.NEXT;
			case RETURN:
				return StepCmd.RETURN;
			case UNTIL:
				return StepCmd.UNTIL;
			case EXTENDED:
				return StepCmd.EXTENDED;
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
				return model.gateFuture(thread.console("advance"));
			default:
				return model.gateFuture(thread.step(convertToGdb(kind)));
		}
	}

	protected void invalidateRegisterCaches() {
		stack.invalidateRegisterCaches();
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return impl.gateFuture(thread.setActive(false));
	}

	public GdbModelTargetBreakpointLocation breakpointHit(GdbBreakpointHitReason reason) {
		GdbStackFrame frame = reason.getFrame(thread);
		GdbModelTargetStackFrame targetFrame = stack.getTargetFrame(frame);
		long bpId = reason.getBreakpointId();
		return impl.session.breakpoints.breakpointHit(bpId, targetFrame);
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		GdbState gdbState = sco.getState();
		CompletableFuture<Void> result = AsyncUtils.NIL;
		if (gdbState == GdbState.STOPPED) {
			Msg.debug(this, "Updating stack for " + this);
			result = CompletableFuture.allOf(updateInfo(), stack.stateChanged(sco));
		}
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, state = convertState(gdbState), //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay() //
		), sco.getReason().desc());
		return result;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		updateInfo();
	}

}
