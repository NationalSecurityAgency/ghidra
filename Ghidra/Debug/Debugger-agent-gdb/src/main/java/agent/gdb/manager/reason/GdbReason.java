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
package agent.gdb.manager.reason;

import java.util.Map;
import java.util.function.Function;

import com.google.common.collect.ImmutableMap;

import agent.gdb.manager.GdbState;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import ghidra.util.Msg;

/**
 * Indicates the reason for a thread's state to change, usually only when {@link GdbState#STOPPED}
 * 
 * This concept is native to GDB. When a thread stops, GDB may communicate the reason, e.g., a
 * breakpoint was hit, or the thread exited. The manager attempts to parse information for the
 * reasons it understands and provides it in e.g., a {@link GdbBreakpointHitReason}. If GDB provides
 * a reason that is not understood by the manager, then {@link GdbReason.Reasons#UNKNOWN} is given.
 * If no reason is provided, then {@link GdbReason.Reasons#NONE} is given.
 */
public interface GdbReason {
	/**
	 * A map of reason strings to reason classes
	 */
	static final Map<String, Function<GdbMiFieldList, ? extends GdbReason>> TYPES =
		new ImmutableMap.Builder<String, Function<GdbMiFieldList, ? extends GdbReason>>()
				.put("signal-received", GdbSignalReceivedReason::new)
				.put("breakpoint-hit", GdbBreakpointHitReason::new)
				.put("end-stepping-range", GdbEndSteppingRangeReason::new)
				.put("exited", GdbExitedReason::new)
				.put("exited-normally", GdbExitNormallyReason::new)
				.build();

	/**
	 * Reasons other than those given by GDB
	 */
	enum Reasons implements GdbReason {
		/**
		 * No reason was given
		 */
		NONE("No reason"),
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

	/**
	 * Process the parsed reason information to get the reason for a state change
	 * 
	 * @param info the parsed information, i.e., the map containing "{@code reason={...}}"
	 * @return the reason
	 */
	static GdbReason getReason(GdbMiFieldList info) {
		String reasonStr = info.getString("reason");
		if (reasonStr == null) {
			return Reasons.NONE;
		}
		Function<GdbMiFieldList, ? extends GdbReason> cons = TYPES.get(reasonStr);
		if (cons == null) {
			Msg.warn(GdbReason.class, "Unknown stop reason: " + reasonStr);
			return Reasons.UNKNOWN;
		}
		return cons.apply(info);
	}

	public String desc();
}
