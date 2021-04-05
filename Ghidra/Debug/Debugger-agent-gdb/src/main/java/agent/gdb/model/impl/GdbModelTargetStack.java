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
import java.util.stream.Collectors;

import agent.gdb.manager.GdbStackFrame;
import agent.gdb.manager.GdbThread;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetStack extends
		DefaultTargetObject<GdbModelTargetStackFrame, GdbModelTargetThread> implements TargetStack {
	public static final String NAME = "Stack";

	protected final GdbModelImpl impl;
	protected final GdbModelTargetInferior inferior;
	protected final GdbThread thread;

	protected final Map<Integer, GdbModelTargetStackFrame> framesByLevel = new WeakValueHashMap<>();

	public GdbModelTargetStack(GdbModelTargetThread thread, GdbModelTargetInferior inferior) {
		super(thread.impl, thread, NAME, "Stack");
		this.impl = thread.impl;
		this.inferior = inferior;
		this.thread = thread.thread;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return thread.listStackFrames().thenAccept(f -> {
			List<GdbModelTargetStackFrame> frames;
			synchronized (this) {
				frames = f.stream().map(this::getTargetFrame).collect(Collectors.toList());
			}
			setElements(frames, "Refreshed");
			//Msg.debug(this, "Completed stack frames update");
		});
	}

	protected synchronized GdbModelTargetStackFrame getTargetFrame(GdbStackFrame frame) {
		return framesByLevel.compute(frame.getLevel(), (l, f) -> {
			if (f == null) {
				return new GdbModelTargetStackFrame(this, parent, inferior, frame);
			}
			f.setFrame(frame);
			return f;
		});
	}

	protected synchronized GdbModelTargetStackFrame getTargetFrameByLevel(int i) {
		return framesByLevel.get(i);
	}

	protected void invalidateRegisterCaches() {
		for (GdbModelTargetStackFrame frame : framesByLevel.values()) {
			frame.invalidateRegisterCaches();
		}
	}

	/**
	 * Re-fetch the stack frames, generating events for updates
	 * 
	 * <p>
	 * GDB doesn't produce stack change events, but they should only ever happen by running a
	 * target. Thus, every time we're STOPPED, this method should be called.
	 */
	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return requestElements(true).thenCompose(__ -> {
			GdbModelTargetStackFrame innermost = framesByLevel.get(0);
			if (innermost != null) {
				return innermost.stateChanged(sco);
			}
			return AsyncUtils.NIL;
		}).exceptionally(e -> {
			impl.reportError(this, "Could not update stack " + this + " on STOPPED", e);
			return null;
		});
	}
}
