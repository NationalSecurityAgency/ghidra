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
package ghidra.app.plugin.core.debug.stack;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * A fake frame which can be used to evaluate variables for which an actual frame is not necessary
 * or not available.
 *
 * <p>
 * This "frame" can only evaluate static / global variables. Neither register variables nor stack
 * variables can be evaluated. The reason for excluding registers is because some register values
 * may be saved to the stack, so the values in the bank may not be the correct value in the context
 * of a given stack frame. Based on an inspection of a variable's storage, it may not be necessary
 * to attempt a stack unwind to evaluate it. If that is the case, this "frame" may be used to
 * evaluate it where a frame interface is expected or convenient.
 */
public class FakeUnwoundFrame<T> extends AbstractUnwoundFrame<T> {
	private static final SavedRegisterMap IDENTITY_MAP = new SavedRegisterMap();

	/**
	 * Construct a fake "frame"
	 * 
	 * @param tool the tool requesting interpretation of the frame, which provides context for
	 *            mapped static programs.
	 * @param coordinates the coordinates (trace, thread, snap, etc.) to examine
	 * @param state the machine state, typically the watch value state for the same coordinates. It
	 *            is the caller's (i.e., subclass') responsibility to ensure the given state
	 *            corresponds to the given coordinates.
	 */
	public FakeUnwoundFrame(PluginTool tool, DebuggerCoordinates coordinates,
			PcodeExecutorState<T> state) {
		super(tool, coordinates, state);
	}

	@Override
	public boolean isFake() {
		return true;
	}

	@Override
	public int getLevel() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDescription() {
		return "(No frame required)";
	}

	@Override
	public Address getProgramCounter() {
		return null;
	}

	@Override
	public Function getFunction() {
		return null;
	}

	@Override
	public Address getBasePointer() {
		return null;
	}

	@Override
	public Address getReturnAddress() {
		return null;
	}

	@Override
	public StackUnwindWarningSet getWarnings() {
		return new StackUnwindWarningSet();
	}

	@Override
	public Exception getError() {
		return null;
	}

	@Override
	protected SavedRegisterMap computeRegisterMap() {
		return IDENTITY_MAP;
	}

	@Override
	protected Address computeAddressOfReturnAddress() {
		return null;
	}

	@Override
	protected Address applyBase(long offset) {
		throw new UnsupportedOperationException();
	}
}
