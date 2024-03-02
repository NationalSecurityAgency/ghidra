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

import java.util.Objects;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction;
import ghidra.debug.api.action.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.watch.WatchRow;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.SleighUtils.AddressOf;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.util.TraceAddressSpace;

/**
 * A tracking specification for the address of a given Sleigh expression
 */
public class WatchLocationTrackingSpec implements LocationTrackingSpec {

	public static final String CONFIG_PREFIX = "TRACK_WATCH_";

	private final String expression;
	private final String label;

	public static boolean isTrackable(WatchRow watch) {
		return SleighUtils.recoverAddressOf(null, watch.getExpression()) != null;
	}

	/**
	 * Derive a tracking specification from the given watch
	 * 
	 * @param watch the watch who address to follow
	 * @return the tracking specification
	 */
	public static WatchLocationTrackingSpec fromWatch(WatchRow watch) {
		return new WatchLocationTrackingSpec(watch.getExpression());
	}

	/**
	 * Create a tracking specification from the given expression
	 * 
	 * @param expression the Sleigh expression whose address to follow
	 */
	public WatchLocationTrackingSpec(String expression) {
		this.expression = expression;
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, expression);
		this.label = SleighUtils.generateSleighExpression(addrOf.offset());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof WatchLocationTrackingSpec that)) {
			return false;
		}
		return this.expression.equals(that.expression);
	}

	@Override
	public String getConfigName() {
		return CONFIG_PREFIX + expression;
	}

	@Override
	public String getMenuName() {
		return TrackLocationAction.NAME_PREFIX_WATCH + expression;
	}

	@Override
	public Icon getMenuIcon() {
		return DebuggerResources.ICON_REGISTER_MARKER;
	}

	@Override
	public String computeTitle(DebuggerCoordinates coordinates) {
		return "&(" + expression + ")";
	}

	@Override
	public String getLocationLabel() {
		return label;
	}

	/**
	 * The tracking logic for a watch (Sleigh expression)
	 */
	class WatchLocationTracker implements LocationTracker {
		private AddressSetView reads;
		private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
		private PcodeExecutor<WatchValue> exec = null;
		private PcodeExpression compiled;

		@Override
		public Address computeTraceAddress(ServiceProvider provider,
				DebuggerCoordinates coordinates) {
			if (!Objects.equals(current, coordinates) || exec == null) {
				current = coordinates;
				exec = current.getPlatform() == null ? null
						: DebuggerPcodeUtils.buildWatchExecutor(provider, coordinates);
			}
			else {
				exec.getState().clear();
			}
			if (current.getTrace() == null) {
				return null;
			}
			compiled = DebuggerPcodeUtils.compileExpression(provider, current, expression);
			WatchValue value = compiled.evaluate(exec);
			return value == null ? null : value.address();
		}

		@Override
		public GoToInput getDefaultGoToInput(ServiceProvider provider,
				DebuggerCoordinates coordinates, ProgramLocation location) {
			TracePlatform platform = current.getPlatform();
			String defaultSpace =
				platform == null ? "ram" : platform.getLanguage().getDefaultSpace().getName();
			AddressOf addrOf = SleighUtils.recoverAddressOf(defaultSpace, expression);
			if (addrOf == null) {
				return NoneLocationTrackingSpec.INSTANCE.getDefaultGoToInput(provider, coordinates,
					location);
			}
			return new GoToInput(addrOf.space(),
				SleighUtils.generateSleighExpression(addrOf.offset()));
		}

		@Override
		public boolean affectedByBytesChange(TraceAddressSpace space, TraceAddressSnapRange range,
				DebuggerCoordinates coordinates) {
			return LocationTrackingSpec.changeIsCurrent(space, range, coordinates) &&
				(reads == null || reads.intersects(range.getX1(), range.getX2()));
		}

		@Override
		public boolean affectedByStackChange(TraceStack stack, DebuggerCoordinates coordinates) {
			return false;
		}

		@Override
		public boolean shouldDisassemble() {
			return false;
		}
	}

	@Override
	public LocationTracker getTracker() {
		return new WatchLocationTracker();
	}
}
