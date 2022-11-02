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

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.util.TraceAddressSpace;

/**
 * A specification for automatic navigation of the dynamic listing
 * 
 * <p>
 * TODO: Some of these should be configurable and permit multiple instances so that common
 * configurations can be saved. The most obvious use case would be a Sleigh expression. A user may
 * want 3 different common expressions readily available in the drop-down list. It might make sense
 * to generate a tracking specification from each Watch.
 */
public interface LocationTrackingSpec {

	/**
	 * Codec for saving/restoring the tracking specification
	 */
	public static class TrackingSpecConfigFieldCodec
			implements ConfigFieldCodec<LocationTrackingSpec> {
		@Override
		public LocationTrackingSpec read(SaveState state, String name,
				LocationTrackingSpec current) {
			String specName = state.getString(name, null);
			return LocationTrackingSpecFactory.fromConfigName(specName);
		}

		@Override
		public void write(SaveState state, String name, LocationTrackingSpec value) {
			state.putString(name, value.getConfigName());
		}
	}

	/**
	 * Check if the given trace-space and range refer to memory or the current frame
	 * 
	 * <p>
	 * If the space models memory, the thread and frame are not considered, in case, e.g., the
	 * tracked register is memory-mapped. If the space models registers, the thread and frame are
	 * considered and must match those given in the coordinates. Whatever the case, the span must
	 * include the snap of the coordinates. Otherwise, the change is not considered current.
	 * 
	 * @param space the trace-space, giving thread, frame, and address space
	 * @param range the address range and time span of the change
	 * @param current the current coordinates
	 * @return true if the change affects the tracked address for the given coordinates
	 */
	static boolean changeIsCurrent(TraceAddressSpace space, TraceAddressSnapRange range,
			DebuggerCoordinates current) {
		if (space == null) {
			return false;
		}
		if (!space.getAddressSpace().isMemorySpace()) {
			TraceMemorySpace memSpace = current.getTrace()
					.getMemoryManager()
					.getMemoryRegisterSpace(current.getThread(), current.getFrame(), false);
			if (memSpace == null || memSpace.getAddressSpace() != space.getAddressSpace()) {
				return false;
			}
		}
		if (!range.getLifespan().contains(current.getSnap())) {
			return false;
		}
		return true;
	}

	/**
	 * Get the configuration name
	 * 
	 * <p>
	 * This is the value stored in configuration files to identify this specification
	 * 
	 * @return the configuration name
	 */
	String getConfigName();

	/**
	 * A human-readable name for this specification
	 * 
	 * <p>
	 * This is the text displayed in menus
	 * 
	 * @return the menu name
	 */
	String getMenuName();

	/**
	 * Get the icon for this specification
	 * 
	 * @return the icon
	 */
	Icon getMenuIcon();

	/**
	 * Compute a title prefix to indicate this tracking specification
	 * 
	 * @param thread the provider's current thread
	 * @return a prefix, or {@code null} to use a default
	 */
	String computeTitle(DebuggerCoordinates coordinates);

	/**
	 * Get (or create) the actual location tracking logic
	 * 
	 * <p>
	 * Having a separate object from the spec gives implementations the option of keeping state on a
	 * per-window basis.
	 * 
	 * @return the tracker
	 */
	LocationTracker getTracker();
}
