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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	elements = {
		@TargetElementType(type = DbgModelTargetStackFrameImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class DbgModelTargetStackImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetStack {

	protected final DbgModelTargetThread thread;

	public static final String NAME = "Stack";

	protected final Map<Integer, DbgModelTargetStackFrameImpl> framesByLevel =
		new WeakValueHashMap<>();

	public DbgModelTargetStackImpl(DbgModelTargetThread thread, DbgModelTargetProcess process) {
		super(thread.getModel(), thread, NAME, "Stack");
		this.thread = thread;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return thread.getThread().listStackFrames().thenAccept(f -> {
			List<TargetObject> frames;
			synchronized (this) {
				frames = f.stream().map(this::getTargetFrame).collect(Collectors.toList());
			}
			// TODO: This might be a case where "move" is useful
			setElements(frames, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized DbgModelTargetStackFrame getTargetFrame(DbgStackFrame frame) {
		return framesByLevel.compute(frame.getLevel(), (l, f) -> {
			if (f == null) {
				return new DbgModelTargetStackFrameImpl(this, thread, frame);
			}
			f.setFrame(frame);
			return f;
		});
	}

	/*
	public void invalidateRegisterCaches() {
		setElements(List.of(), Map.of(), "Invalidated");
		for (DbgModelTargetStackFrameImpl frame : framesByLevel.values()) {
			frame.invalidateRegisterCaches();
		}
	}
	*/

	public void threadStateChangedSpecific(DbgState state, DbgReason reason) {
		if (!state.equals(DbgState.RUNNING)) {
			requestElements(true).exceptionally(e -> {
				Msg.error(this, "Could not update stack " + this + " on STOPPED");
				return null;
			});
		}
	}
}
