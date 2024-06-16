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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.manager.FridaFrame;
import agent.frida.manager.FridaReason;
import agent.frida.manager.FridaState;
import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.iface2.FridaModelTargetStack;
import agent.frida.model.iface2.FridaModelTargetStackFrame;
import agent.frida.model.iface2.FridaModelTargetThread;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = FridaModelTargetStackFrameImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class FridaModelTargetStackImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetStack {

	protected final FridaModelTargetThread thread;

	public static final String NAME = "Stack";

	protected final Map<Integer, FridaModelTargetStackFrameImpl> framesByLevel =
		new WeakValueHashMap<>();

	public FridaModelTargetStackImpl(FridaModelTargetThread thread, FridaModelTargetProcess process) {
		super(thread.getModel(), thread, NAME, "Stack");
		this.thread = thread;
		requestElements(RefreshBehavior.REFRESH_NEVER);
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
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
	public synchronized FridaModelTargetStackFrame getTargetFrame(FridaFrame frame) {
		return framesByLevel.compute(frame.getFrameID(), (l, f) -> {
			if (f == null) {
				return new FridaModelTargetStackFrameImpl(this, thread, frame);
			}
			f.setFrame(frame);
			return f;
		});
	}

	public void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		if (state.equals(FridaState.FRIDA_THREAD_STOPPED)) {
			requestElements(RefreshBehavior.REFRESH_ALWAYS).thenAccept(__ -> {
				for (TargetObject element : getCachedElements().values()) {
					if (element instanceof FridaModelTargetStackFrame) {
						FridaModelTargetStackFrameImpl frame =
							(FridaModelTargetStackFrameImpl) element;
						frame.threadStateChangedSpecific(state, reason);
					}
				}
			});
		}
	}

}
