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
package ghidra.trace.model.memory;

import java.util.stream.Stream;

public enum TraceMemoryState {
	/**
	 * The value was not observed at the snapshot
	 */
	UNKNOWN(true, false),
	/**
	 * The value was observed at the snapshot
	 */
	KNOWN(false, true),
	/**
	 * The value could not be observed at the snapshot
	 */
	ERROR(false, false);

	public static final TraceMemoryState IMPLIED_BY_NULL =
		Stream.of(values()).filter(TraceMemoryState::impliedByNull).findFirst().orElseThrow();

	public static TraceMemoryState orImplied(TraceMemoryState s) {
		return s == null ? IMPLIED_BY_NULL : s;
	}

	private final boolean impliedByNull;
	private final boolean truncates;

	private TraceMemoryState(boolean impliedByNull, boolean truncates) {
		this.impliedByNull = impliedByNull;
		this.truncates = truncates;
	}

	public boolean impliedByNull() {
		return impliedByNull;
	}

	public boolean truncates() {
		return truncates;
	}
}
