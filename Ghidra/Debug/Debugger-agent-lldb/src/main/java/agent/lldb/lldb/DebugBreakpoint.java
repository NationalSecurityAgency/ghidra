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
package agent.lldb.lldb;

import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

/**
 * A wrapper for breakpoint variations
 */
public interface DebugBreakpoint {
	public static enum BreakType {
		CODE, DATA, TIME, INLINE;
	}

	public static class BreakFullType {
		public final BreakType breakType;

		public BreakFullType(BreakType breakType) {
			this.breakType = breakType;
		}
	}

	public static enum BreakFlags implements BitmaskUniverse {
		GO_ONLY(1 << 0), //
		DEFERRED(1 << 1), //
		ENABLED(1 << 2), //
		ADDER_ONLY(1 << 3), //
		ONE_SHOT(1 << 4), //
		;

		private BreakFlags(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum BreakAccess implements BitmaskUniverse {
		READ(1 << 0), //
		WRITE(1 << 1), //
		EXECUTE(1 << 2), //
		READ_WRITE(1 << 3), //
		;

		private BreakAccess(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static class BreakDataParameters {
		public int size;
		public BitmaskSet<BreakAccess> access;

		public BreakDataParameters(int size, BitmaskSet<BreakAccess> access) {
			this.size = size;
			this.access = access;
		}
	}

}
