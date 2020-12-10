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
package agent.dbgeng.dbgeng;

import agent.dbgeng.dbgeng.DebugRunningProcess.Description.ProcessDescriptionFlags;
import ghidra.comm.util.BitmaskUniverse;

/**
 * Information about a running process, not necessarily a debugged process.
 */
public interface DebugRunningProcess {
	/**
	 * Description of a running process
	 */
	public static class Description {
		public static enum ProcessDescriptionFlags implements BitmaskUniverse {
			NO_PATHS(1 << 0), //
			NO_SERVICES(1 << 1), //
			NO_MTS_PACKAGES(1 << 2), //
			NO_COMMAND_LINE(1 << 3), //
			NO_SESSION_ID(1 << 4), //
			NO_USER_NAME(1 << 5), //
			;

			ProcessDescriptionFlags(int mask) {
				this.mask = mask;
			}

			private final int mask;

			@Override
			public long getMask() {
				return mask;
			}
		}

		public Description(int systemId, String exeName, String description) {
			this.systemId = systemId;
			this.exeName = exeName;
			this.description = description;
		}

		private final int systemId;
		private final String exeName;
		private final String description;

		/**
		 * The system ID (PID) for the process.
		 * 
		 * @return the PID
		 */
		public int getSystemId() {
			return systemId;
		}

		/**
		 * The name of the executable defining the process
		 * 
		 * @return the name
		 */
		public String getExecutableName() {
			return exeName;
		}

		/**
		 * A textual description of the process.
		 * 
		 * @return the description
		 */
		public String getDescription() {
			return description;
		}

		@Override
		public String toString() {
			return String.format("PID:%d, EXE:%s, Description:%s", systemId, exeName, description);
		}
	}

	/**
	 * The system ID (PID) for the process.
	 * 
	 * @return the PID
	 */
	int getSystemId();

	/**
	 * Get the "full" description of the process.
	 * 
	 * @param flags indicate which information to include in the description
	 * @return the description
	 */
	Description getFullDescription(ProcessDescriptionFlags... flags);

	/**
	 * The name of the executable defining the process.
	 * 
	 * @param flags indicate which information to include in the description
	 * @return the name
	 */
	String getExecutableName(ProcessDescriptionFlags... flags);

	/**
	 * A textual description of the process.
	 * 
	 * @param flags indicate which information to include in the description
	 * @return the description
	 */
	String getDescription(ProcessDescriptionFlags... flags);
}
