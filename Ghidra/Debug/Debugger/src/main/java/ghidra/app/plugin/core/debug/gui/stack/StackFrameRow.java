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

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.stack.TraceStackFrame;

public class StackFrameRow {
	public static class Synthetic extends StackFrameRow {
		private Address pc;

		public Synthetic(DebuggerLegacyStackPanel panel, Address pc) {
			super(panel);
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

	private final DebuggerLegacyStackPanel panel;

	final TraceStackFrame frame;
	private int level;

	public StackFrameRow(DebuggerLegacyStackPanel panel, TraceStackFrame frame) {
		this.panel = panel;
		this.frame = frame;
		this.level = frame.getLevel();
	}

	private StackFrameRow(DebuggerLegacyStackPanel panel) {
		this.panel = panel;
		this.frame = null;
		this.level = 0;
	}

	public int getFrameLevel() {
		return level;
	}

	public long getSnap() {
		return panel.current.getSnap();
	}

	public Address getProgramCounter() {
		return frame.getProgramCounter(getSnap());
	}

	public String getComment() {
		return frame == null ? "" : frame.getComment(getSnap());
	}

	public void setComment(String comment) {
		try (Transaction tx =
			frame.getStack().getThread().getTrace().openTransaction("Frame comment")) {
			frame.setComment(getSnap(), comment);
		}
	}

	public boolean isCommentable() {
		return frame != null;
	}

	public Function getFunction() {
		return panel.provider.getFunction(getProgramCounter());
	}

	protected void update() {
		assert frame != null; // Should never update a synthetic stack
		level = frame.getLevel();
	}
}
