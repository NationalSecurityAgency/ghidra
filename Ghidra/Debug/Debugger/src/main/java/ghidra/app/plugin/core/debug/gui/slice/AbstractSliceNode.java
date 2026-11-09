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
package ghidra.app.plugin.core.debug.gui.slice;

import docking.widgets.gtreetable.GTreeTableNode;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.trace.model.Trace;

abstract class AbstractSliceNode extends GTreeTableNode {
	protected final Trace trace;

	private boolean checked;

	public AbstractSliceNode(String name, Trace trace) {
		this.trace = trace;
		super(name);
	}

	public abstract String getLocation();

	public abstract Address getAddress();

	public abstract long getSnap();

	public abstract boolean displaySnap();

	public abstract Program getImage();

	public abstract Address getStaticPc();

	public abstract byte[] getBytes();

	public boolean isChecked() {
		return checked;
	}

	public void setChecked(boolean checked) {
		this.checked = checked;
	}

	public InstructionSliceNode newInstructionNode(SliceEdgeType type, Instruction instruction,
			long snap, boolean displaySnap, DebuggerAddressTranslator ms) {
		return new InstructionSliceNode(type, trace, instruction, snap, displaySnap, ms);
	}

	public DataSliceNode newDataNode(SliceEdgeType type, Data data, long snap,
			boolean displaySnap) {
		return new DataSliceNode(type, trace, data, snap, displaySnap, getImage(), getStaticPc());
	}

	public UnitSliceNode<?> newUnitNode(SliceEdgeType type, CodeUnit unit, long snap,
			boolean displaySnap, DebuggerAddressTranslator ms) {
		return switch (unit) {
			case Instruction instruction -> newInstructionNode(type, instruction, snap,
				displaySnap, ms);
			case Data data -> newDataNode(type, data, snap, displaySnap);
			default -> throw new AssertionError();
		};
	}
}
