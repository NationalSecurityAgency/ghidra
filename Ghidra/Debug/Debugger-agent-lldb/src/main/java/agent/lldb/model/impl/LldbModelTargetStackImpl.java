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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBFrame;
import SWIG.StateType;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = LldbModelTargetStackFrameImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetStackImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetStack {

	protected final LldbModelTargetThread thread;

	public static final String NAME = "Stack";

	protected final Map<Integer, LldbModelTargetStackFrameImpl> framesByLevel =
		new WeakValueHashMap<>();

	public LldbModelTargetStackImpl(LldbModelTargetThread thread, LldbModelTargetProcess process) {
		super(thread.getModel(), thread, NAME, "Stack");
		this.thread = thread;
		requestElements(false);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listStackFrames(thread.getThread()).thenAccept(f -> {
			List<TargetObject> frames;
			synchronized (this) {
				frames =
					f.values().stream().map(this::getTargetFrame).collect(Collectors.toList());
			}
			setElements(frames, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized LldbModelTargetStackFrame getTargetFrame(SBFrame frame) {
		return framesByLevel.compute((int) frame.GetFrameID(), (l, f) -> {
			if (f == null) {
				return new LldbModelTargetStackFrameImpl(this, thread, frame);
			}
			f.setFrame(frame);
			return f;
		});
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		if (state.equals(StateType.eStateStopped)) {
			requestElements(true).thenAccept(__ -> {
				for (TargetObject element : getCachedElements().values()) {
					if (element instanceof LldbModelTargetStackFrame) {
						LldbModelTargetStackFrameImpl frame =
							(LldbModelTargetStackFrameImpl) element;
						frame.threadStateChangedSpecific(state, reason);
					}
				}
			});
		}
	}

}
