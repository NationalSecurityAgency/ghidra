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

public class JdiVMThreadGroup {
	private final int iid;
	private final String type;
	private final Long pid;
	private final Long exitCode;
	private final String executable;
	// TODO: cores

	public JdiVMThreadGroup(int iid, String type, Long pid, Long exitCode,
			String executable) {
		this.iid = iid;
		this.type = type;
		this.pid = pid;
		this.exitCode = exitCode;
		this.executable = executable;
	}

	public int getInferiorId() {
		return iid;
	}

	public String getType() {
		return type;
	}

	public Long getPid() {
		return pid;
	}

	public Long getExitCode() {
		return exitCode;
	}

	public String getExecutable() {
		return executable;
	}
}
