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
package ghidra.app.plugin.core.debug.gui.stack;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class StackFrameRow {
	public static class Synthetic extends StackFrameRow {
		private Address pc;

		public Synthetic(DebuggerStackProvider provider, Address pc) {
			super(provider);
			this.pc = pc;
		}

		public void updateProgramCounter(Address pc) {
			this.pc = pc;
		}

		@Override
		public Address getProgramCounter() {
			return pc;
		}
	}

	private final DebuggerStackProvider provider;

	final TraceStackFrame frame;
	private int level;

	public StackFrameRow(DebuggerStackProvider provider, TraceStackFrame frame) {
		this.provider = provider;
		this.frame = frame;
		this.level = frame.getLevel();
	}

	private StackFrameRow(DebuggerStackProvider provider) {
		this.provider = provider;
		this.frame = null;
		this.level = 0;
	}

	public int getFrameLevel() {
		return level;
	}

	public long getSnap() {
		return provider.current.getSnap();
	}

	public Address getProgramCounter() {
		return frame.getProgramCounter(getSnap());
	}

	public String getComment() {
		return frame == null ? "" : frame.getComment(getSnap());
	}

	public void setComment(String comment) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(frame.getStack().getThread().getTrace(), "Frame comment")) {
			frame.setComment(getSnap(), comment);
		}
	}

	public boolean isCommentable() {
		return frame != null;
	}

	public Function getFunction() {
		if (provider.mappingService == null) {
			return null;
		}
		TraceThread curThread = provider.current.getThread();
		if (curThread == null) {
			return null;
		}
		Address pc = getProgramCounter();
		if (pc == null) {
			return null;
		}
		TraceLocation dloc = new DefaultTraceLocation(curThread.getTrace(),
			curThread, Range.singleton(getSnap()), pc);
		ProgramLocation sloc = provider.mappingService.getOpenMappedLocation(dloc);
		if (sloc == null) {
			return null;
		}
		return sloc.getProgram().getFunctionManager().getFunctionContaining(sloc.getAddress());
	}

	protected void update() {
		assert frame != null; // Should never update a synthetic stack
		level = frame.getLevel();
	}
}
