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
package ghidra.app.plugin.core.debug.gui.action;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.util.TraceAddressSpace;

/**
 * The actual tracking logic for a location tracking spec
 * 
 * <p>
 * In simple cases, the spec can implement this interface and return itself in
 * {@link LocationTrackingSpec#getTracker()}. If the tracker needs some state, then the spec should
 * create a separate tracker.
 */
public interface LocationTracker {

	/**
	 * Compute the trace address to "goto"
	 * 
	 * <p>
	 * If the coordinates indicate emulation, i.e., the schedule is non-empty, the trace manager
	 * will already have performed the emulation and stored the results in a "scratch" snap. In
	 * general, the location should be computed using that snap, i.e.,
	 * {@link DebuggerCoordinates#getViewSnap()} rather than {@link DebuggerCoordinates#getSnap()}.
	 * The address returned must be in the host platform's language, i.e., please use
	 * {@link TracePlatform#mapGuestToHost(Address)}.
	 * 
	 * @param tool the tool containing the provider
	 * @param coordinates the trace, thread, snap, etc., of the tool
	 * @return the address to navigate to
	 */
	CompletableFuture<Address> computeTraceAddress(PluginTool tool,
			DebuggerCoordinates coordinates);

	/**
	 * Get the suggested input if the user activates "Go To" while this tracker is active
	 *
	 * @param tool the tool containing the provider
	 * @param coordinates the user's current coordinates
	 * @param location the user's current location
	 * @return the suggested address or Sleigh expression
	 */
	GoToInput getDefaultGoToInput(PluginTool tool, DebuggerCoordinates coordinates,
			ProgramLocation location);

	// TODO: Is there a way to generalize these so that other dependencies need not
	// have their own bespoke methods?

	/**
	 * Check if the address should be recomputed given the indicated value change
	 * 
	 * @param space the space (address space, thread, frame) where the change occurred
	 * @param range the range (time and space) where the change occurred
	 * @param coordinates the provider's current coordinates
	 * @return true if re-computation and "goto" is warranted
	 */
	boolean affectedByBytesChange(TraceAddressSpace space,
			TraceAddressSnapRange range, DebuggerCoordinates coordinates);

	/**
	 * Check if the address should be recomputed given the indicated stack change
	 * 
	 * @param stack the stack that changed (usually it's PC / return offset)
	 * @param coordinates the provider's current coordinates
	 * @return true if re-computation and "goto" is warranted
	 */
	boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates);
}
