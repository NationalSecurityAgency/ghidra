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
package ghidra.trace.database.space;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.util.TraceAddressSpace;

public interface DBTraceSpaceKey extends TraceAddressSpace {
	static class DefaultDBTraceSpaceKey implements DBTraceSpaceKey {
		private final DBTraceThread thread;
		private final AddressSpace space;
		private final int frameLevel;

		private DefaultDBTraceSpaceKey(DBTraceThread thread, AddressSpace space, int frameLevel) {
			this.thread = thread;
			this.space = space;
			this.frameLevel = frameLevel;
		}

		@Override
		public AddressSpace getAddressSpace() {
			return space;
		}

		@Override
		public DBTraceThread getThread() {
			return thread;
		}

		@Override
		public int getFrameLevel() {
			return frameLevel;
		}
	}

	static DBTraceSpaceKey create(AddressSpace space, DBTraceThread thread, int frameLevel) {
		return new DefaultDBTraceSpaceKey(thread, space, frameLevel);
	}

	@Override
	DBTraceThread getThread();
}
