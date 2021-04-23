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
	READ(1 << 0),
	WRITE(1 << 1),
	HW_EXECUTE(1 << 2),
	SW_EXECUTE(1 << 3);

	public static class TraceBreakpointKindSet extends AbstractSetDecorator<TraceBreakpointKind> {
		public static TraceBreakpointKindSet of(TraceBreakpointKind... kinds) {
			return new TraceBreakpointKindSet(Set.of(kinds));
		}

		public static TraceBreakpointKindSet copyOf(Collection<TraceBreakpointKind> kinds) {
			return new TraceBreakpointKindSet(Set.copyOf(kinds));
		}

		/**
		 * Convert a comma-separated list of kind names to a set of kinds.
		 * 
		 * @param encoded the encoded list
		 * @param strict true to report unrecognized kinds, false to ignore
		 * @return the decoded set
		 */
		public static TraceBreakpointKindSet decode(String encoded, boolean strict) {
			Set<TraceBreakpointKind> result = EnumSet.noneOf(TraceBreakpointKind.class);
			Set<String> names = new HashSet<>(Set.of(encoded.toUpperCase().split(",")));
			for (TraceBreakpointKind k : values()) {
				if (names.remove(k.name())) {
					result.add(k);
				}
			}
			if (strict && !names.isEmpty()) {
				throw new IllegalArgumentException(names.toString());
			}
			return new TraceBreakpointKindSet(result);
		}

		/**
		 * Convert a set (or collection) of kinds to a comma-separated list of names.
		 * 
		 * The list is always encoded in order of the declaration of kinds (enum order).
		 * 
		 * @param col the set
		 * @return the encoded list
		 */
		public static String encode(Collection<TraceBreakpointKind> col) {
			StringBuilder sb = new StringBuilder();
			boolean first = true;
			for (TraceBreakpointKind k : values()) {
				if (col.contains(k)) {
					if (!first) {
						sb.append(',');
					}
					first = false;
					sb.append(k.name());
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

	private final byte bits;

	TraceBreakpointKind(int mask) {
		this.bits = (byte) mask;
	}

	public byte getBits() {
		return bits;
	}
}
