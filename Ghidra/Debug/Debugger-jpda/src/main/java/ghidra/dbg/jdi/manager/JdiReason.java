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
package ghidra.dbg.jdi.manager;

import com.sun.jdi.ThreadReference;

/**
 * Indicates the reason for a thread's state to change, usually only when
 * {@link ThreadReference#STOPPED}
 * 
 * This concept is native to JDI. When a thread stops, JDI may communicate the reason, e.g., a
 * breakpoint was hit, or the thread exited. The manager attempts to parse information for the
 * reasons it understands and provides it in e.g., a {@link JdiBreakpointHitReason}. If JDI provides
 * a reason that is not understood by the manager, then {@link JdiReason.Reasons#UNKNOWN} is given.
 * If no reason is provided, then {@link JdiReason.Reasons#NONE} is given.
 */
public interface JdiReason {
	/**
	 * A map of reason strings to reason classes
	 */
	/*
	static final Map<String, Function<JdiMiFieldList, ? extends JdiReason>> TYPES =
		new ImmutableMap.Builder<String, Function<JdiMiFieldList, ? extends JdiReason>>()
				.put("signal-received", JdiSignalReceivedReason::new)
				.put("breakpoint-hit", JdiBreakpointHitReason::new)
				.put("end-stepping-range", JdiEndSteppingRangeReason::new)
				.put("exited", JdiExitedReason::new)
				.put("exited-normally", JdiExitNormallyReason::new)
				.build();
	*/

	/**
	 * Reasons other than those given by JDI
	 */
	enum Reasons implements JdiReason {
		/**
		 * No reason was given
		 */
		NONE("No reason"),
		/**
		 * Step complete
		 */
		STEP("Step"),
		/**
		 * Target interrupted
		 */
		INTERRUPT("Interrupt"),
		/**
		 * Breakpoint hit
		 */
		BREAKPOINT_HIT("Breakpoint"),
		/**
		 * Watchpoint hit
		 */
		WATCHPOINT_HIT("Watchpoint"),
		/**
		 * Access watchpoint hit
		 */
		ACCESS_WATCHPOINT_HIT("Access Watchpoint"),
		/**
		 * Target resumed
		 */
		RESUMED("Resumed"),
		/**
		 * A reason was given, but the manager does not understand it
		 */
		UNKNOWN("Unknown");

		final String desc;

		private Reasons(String desc) {
			this.desc = desc;
		}

		@Override
		public String desc() {
			return desc;
		}
	}

	public String desc();
}
