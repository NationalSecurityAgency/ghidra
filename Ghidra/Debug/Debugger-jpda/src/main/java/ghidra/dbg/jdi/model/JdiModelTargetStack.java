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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.*;

import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	elements = {
		@TargetElementType(type = JdiModelTargetStackFrame.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetStack extends JdiModelTargetObjectImpl
		implements TargetStack {

	protected final JdiModelTargetThread thread;

	protected final Map<Location, JdiModelTargetStackFrame> framesByLocation =
		new WeakValueHashMap<>();
	protected final Map<Integer, JdiModelTargetStackFrame> framesByLevel = new WeakValueHashMap<>();

	public JdiModelTargetStack(JdiModelTargetThread thread) {
		super(thread, "Stack");
		this.thread = thread;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		List<JdiModelTargetStackFrame> targetFrames = new ArrayList<>();
		List<StackFrame> frames;
		try {
			frames = thread.thread.frames();
			int i = 0;
			for (StackFrame frame : frames) {
				JdiModelTargetStackFrame targetFrame = getTargetFrame(i++, frame);
				targetFrames.add(targetFrame);
			}
			setElements(targetFrames, Map.of(), "Refreshed");
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore e.printStackTrace();
		}
		return CompletableFuture.completedFuture(null);
	}

	protected synchronized JdiModelTargetStackFrame getTargetFrame(int level, StackFrame frame) {
		return framesByLocation.compute(frame.location(), (l, f) -> {
			if (f == null || f.getFrameLevel() != level) {
				JdiModelTargetStackFrame tf =
					new JdiModelTargetStackFrame(this, thread, level, frame, true);
				framesByLevel.put(level, tf);
				return tf;
			}
			framesByLevel.put(level, f);
			f.setFrame(level, frame);
			return f;
		});
	}

	public JdiModelTargetStackFrame getTargetFrame(StackFrame frame) {
		for (JdiModelTargetStackFrame f : framesByLocation.values()) {
			if (f.frame.equals(frame)) {
				return f;
			}
		}
		return null;
	}

	public JdiModelTargetStackFrame getTargetFrame(int level) {
		return framesByLevel.get(Integer.valueOf(level));
	}

	/**
	 * Re-fetch the stack frames, generating events for updates
	 * 
	 * JDI doesn't produce stack change events, but they should only ever happen by running a
	 * target. Thus, every time we're STOPPED, this method should be called.
	 * 
	 * @return null
	 */
	protected CompletableFuture<?> update() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return fetchElements(true).exceptionally(e -> {
			Msg.error(this, "Could not update stack " + this + " on STOPPED");
			return null;
		});
	}

	public void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}
}
