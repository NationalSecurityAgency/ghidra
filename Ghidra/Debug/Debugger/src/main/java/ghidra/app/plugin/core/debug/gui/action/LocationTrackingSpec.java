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

import java.util.Map;
import java.util.TreeMap;

import javax.swing.Icon;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A "specification" for automatic navigation of the dynamic listing
 * 
 * <p>
 * TODO: Some of these should be configurable, and permit multiple instances, so that common
 * configurations can be saved. The most obvious use case would be a SLEIGH expression. A user may
 * want 3 different common expressions readily available in the drop-down list.
 */
public interface LocationTrackingSpec extends ExtensionPoint {
	class Private {
		private final Map<String, LocationTrackingSpec> specsByName = new TreeMap<>();
		private final ChangeListener classListener = this::classesChanged;

		private Private() {
			ClassSearcher.addChangeListener(classListener);
		}

		private synchronized void classesChanged(ChangeEvent evt) {
			MiscellaneousUtils.collectUniqueInstances(LocationTrackingSpec.class, specsByName,
				LocationTrackingSpec::getConfigName);
		}
	}

	Private PRIVATE = new Private();

	public static class TrackingSpecConfigFieldCodec
			implements ConfigFieldCodec<LocationTrackingSpec> {
		@Override
		public LocationTrackingSpec read(SaveState state, String name,
				LocationTrackingSpec current) {
			String specName = state.getString(name, null);
			return fromConfigName(specName);
		}

		@Override
		public void write(SaveState state, String name, LocationTrackingSpec value) {
			state.putString(name, value.getConfigName());
		}
	}

	static boolean changeIsCurrent(TraceAddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates current) {
		if (space == null || space.getThread() != current.getThread()) {
			return false;
		}
		if (space.getFrameLevel() != current.getFrame()) {
			return false;
		}
		if (!range.getLifespan().contains(current.getSnap())) {
			return false;
		}
		return true;
	}

	static LocationTrackingSpec fromConfigName(String name) {
		synchronized (PRIVATE) {
			return PRIVATE.specsByName.get(name);
		}
	}

	static Map<String, LocationTrackingSpec> allSpecs() {
		synchronized (PRIVATE) {
			return Map.copyOf(PRIVATE.specsByName);
		}
	}

	String getConfigName();

	String getMenuName();

	Icon getMenuIcon();

	/**
	 * Compute a title prefix to indicate this tracking specification
	 * 
	 * @param thread the provider's current thread
	 * @return a prefix, or {@code null} to use a default
	 */
	String computeTitle(DebuggerCoordinates coordinates);

	/**
	 * Compute the trace address to "goto"
	 * 
	 * <p>
	 * If the coordinates indicate emulation, i.e., the schedule is non-empty, the trace manager
	 * will already have performed the emulation and stored the results in a "scratch" snap. In
	 * general, the location should be computed using that snap (@code emuSnap) rather than the one
	 * indicated in {@code coordinates}.
	 * 
	 * @param tool the tool containing the provider
	 * @param coordinates the trace, thread, snap, etc., of the tool
	 * @param emuSnap the "scratch" snap storing emulated state
	 * @return the address to navigate to
	 */
	Address computeTraceAddress(PluginTool tool, DebuggerCoordinates coordinates, long emuSnap);

	// TODO: Is there a way to generalize these so that other dependencies need not
	// have their own bespoke methods?

	/**
	 * Check if the address should be recomputed given the indicated register value change
	 * 
	 * @param space the space (address space, thread, frame) where the change occurred
	 * @param range the range (time and space) where the change occurred
	 * @param coordinates the provider's current coordinates
	 * @return true if re-computation and "goto" is warranted
	 */
	boolean affectedByRegisterChange(TraceAddressSpace space,
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
