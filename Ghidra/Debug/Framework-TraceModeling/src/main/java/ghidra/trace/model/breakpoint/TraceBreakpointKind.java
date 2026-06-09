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
package ghidra.trace.model.breakpoint;

import java.util.*;

import org.apache.commons.collections4.set.AbstractSetDecorator;

/**
 * The kind of breakpoint
 * 
 * <p>
 * This identifies the sort of access that would trap execution
 * 
 * <p>
 * TODO: This is identical to {@code TargetBreakpointKind} (not in the classpath here). Is there a
 * common place we could factor both? Should we? CAUTION: Encoding in a trace database depends on
 * this enum's {@code bits} field, so we must take care not to introduce a dependency that would
 * open us up to database breaks if the common enum changes.
 */
public enum TraceBreakpointKind {
	READ('R'),
	WRITE('W'),
	HW_EXECUTE('X'),
	SW_EXECUTE('x');

	public static final List<TraceBreakpointKind> VALUES = List.of(values());
	public static final int COUNT = VALUES.size();

	public static class TraceBreakpointKindSet extends AbstractSetDecorator<TraceBreakpointKind> {
		public static final TraceBreakpointKindSet EMPTY = TraceBreakpointKindSet.of();

		public static TraceBreakpointKindSet of(TraceBreakpointKind... kinds) {
			return new TraceBreakpointKindSet(Set.of(kinds));
		}

		public static TraceBreakpointKindSet copyOf(Collection<TraceBreakpointKind> kinds) {
			return new TraceBreakpointKindSet(Set.copyOf(kinds));
		}

		/**
		 * Convert a string of flags to a set of kinds.
		 * <p>
		 * For backwards compatibility, this can also accept a comma-separated list of kind names.
		 * The backwards compatibility will eventually be removed. In the meantime, no string can
		 * exceed 3 flags, as this has to be able to distinguish which encoding to decode, and the
		 * shortest name is {@link #READ}.
		 * 
		 * @param encoded the encoded list
		 * @param strict true to report unrecognized kinds, false to ignore
		 * @return the decoded set
		 */
		public static TraceBreakpointKindSet decode(String encoded, boolean strict) {
			TraceBreakpointKindSet simple = switch (encoded) {
				case "" -> EMPTY;
				case "x", "SW_EXECUTE" -> CommonSet.SWX.kinds();
				case "X", "HW_EXECUTE" -> CommonSet.HWX.kinds();
				case "R", "READ" -> CommonSet.READ.kinds();
				case "W", "WRITE" -> CommonSet.WRITE.kinds();
				case "RW", "READ,WRITE", "WRITE,READ" -> CommonSet.ACCESS.kinds();
				default -> null;
			};
			if (simple != null) {
				return simple;
			}
			/**
			 * Distinguishes 3-flag encoding from shortest comma-names encoding. No sane system
			 * should apply all 4 flags, which would confuse this check.
			 */
			Set<TraceBreakpointKind> result = EnumSet.noneOf(TraceBreakpointKind.class);
			if (encoded.length() < 4) {
				for (TraceBreakpointKind k : VALUES) {
					if (encoded.contains(k.flagStr)) {
						result.add(k);
					}
				}
				// I kind of don't care about "strict" anymore
			}
			else {
				Set<String> names = new HashSet<>(Set.of(encoded.toUpperCase().split(",")));
				for (TraceBreakpointKind k : VALUES) {
					if (names.remove(k.name())) {
						result.add(k);
					}
				}
				if (strict && !names.isEmpty()) {
					throw new IllegalArgumentException(names.toString());
				}
			}
			return new TraceBreakpointKindSet(result);
		}

		/**
		 * Convert a set (or collection) of kinds to a string of flags
		 * <p>
		 * The list is always encoded in order of the declaration of kinds (enum order).
		 * 
		 * @param col the set
		 * @return the encoded list
		 */
		public static String encode(Collection<TraceBreakpointKind> col) {
			StringBuilder sb = new StringBuilder();
			for (TraceBreakpointKind k : VALUES) {
				if (col.contains(k)) {
					sb.append(k.flag);
				}
			}
			return sb.toString();
		}

		public TraceBreakpointKindSet(Set<TraceBreakpointKind> set) {
			super(set);
		}

		@Override
		public String toString() {
			return encode(this);
		}
	}

	public enum CommonSet {
		SWX("Execute (sw)", TraceBreakpointKindSet.of(TraceBreakpointKind.SW_EXECUTE)),
		HWX("Execute (hw)", TraceBreakpointKindSet.of(TraceBreakpointKind.HW_EXECUTE)),
		READ("Read (hw)", TraceBreakpointKindSet.of(TraceBreakpointKind.READ)),
		WRITE("Write (hw)", TraceBreakpointKindSet.of(TraceBreakpointKind.WRITE)),
		ACCESS("Access (hw)", TraceBreakpointKindSet.of(
			TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));

		public static final List<CommonSet> VALUES = List.of(values());

		private final String display;
		private final TraceBreakpointKindSet kinds;

		private CommonSet(String display, TraceBreakpointKindSet kinds) {
			this.display = display;
			this.kinds = kinds;
		}

		@Override
		public String toString() {
			return display;
		}

		public TraceBreakpointKindSet kinds() {
			return kinds;
		}
	}

	private final char flag;
	private final String flagStr;

	TraceBreakpointKind(char flag) {
		this.flag = flag;
		this.flagStr = "" + flag;
	}
}
