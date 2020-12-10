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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

/**
 * A process which can be attached via SCTL
 */
public class SctlTargetAttachable
		extends DefaultTargetObject<TargetObject, SctlTargetAttachableContainer>
		implements TargetAttachable<SctlTargetAttachable> {

	protected static String indexAttachable(long pid) {
		return PathUtils.makeIndex(pid);
	}

	protected static String keyAttachable(long pid) {
		return PathUtils.makeKey(indexAttachable(pid));
	}

	protected final SctlClient client;

	protected final long pid;
	protected final String cmdLine;

	/**
	 * Construct an attachable process
	 * 
	 * @param container the parent object (associated with the same client)
	 * @param pid the PID of the process
	 * @param cmdLine command line
	 */
	public SctlTargetAttachable(SctlTargetAttachableContainer container, long pid, String cmdLine) {
		super(container.client, container, keyAttachable(pid), "AttachableProcess");
		this.client = container.client;

		this.pid = pid;
		this.cmdLine = cmdLine;

		changeAttributes(List.of(), List.of(), Map.of( //
			"pid", pid, //
			"cmd_line", cmdLine //
		), "Initialized");
	}

	public long getPid() {
		return pid;
	}

	public String getCommandLine() {
		return cmdLine;
	}
}
