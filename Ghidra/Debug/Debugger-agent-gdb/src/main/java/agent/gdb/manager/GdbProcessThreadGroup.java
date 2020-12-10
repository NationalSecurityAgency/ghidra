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
package agent.gdb.manager;

/**
 * A description of an available process
 * 
 * NOTE: This list of available processes can change at any time. The pid may not be valid or
 * describe the same process.
 */
public class GdbProcessThreadGroup {
	private final int pid;
	private final String description;

	public GdbProcessThreadGroup(int pid, String description) {
		this.pid = pid;
		this.description = description;
	}

	/**
	 * Get the process ID
	 * 
	 * @return the PID
	 */
	public int getPid() {
		return pid;
	}

	/**
	 * Get a description of the process, usually the command line
	 * 
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}
}
