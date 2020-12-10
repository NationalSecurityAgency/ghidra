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
package agent.dbgmodel.impl.dbgmodel;

import agent.dbgeng.dbgeng.DebugRunningProcess;
import agent.dbgeng.dbgeng.DebugServerId;
import agent.dbgmodel.dbgmodel.main.ModelObject;

public class DebugRunningProcessImpl
		implements DebugRunningProcess, Comparable<DebugRunningProcessImpl> {

	public DebugRunningProcessImpl(String id, ModelObject object, DebugServerId server) {
		this.object = object;
		this.server = server;
		this.systemId = Integer.decode(id);
	}

	protected final ModelObject object;
	protected final DebugServerId server;
	protected final int systemId;

	@Override
	public int getSystemId() {
		return systemId;
	}

	@Override
	public Description getFullDescription(Description.ProcessDescriptionFlags... flags) {
		return new Description(systemId, object.getSearchKey(), object.toString());
	}

	@Override
	public String getExecutableName(Description.ProcessDescriptionFlags... flags) {
		return getFullDescription(flags).getExecutableName();
	}

	@Override
	public String getDescription(Description.ProcessDescriptionFlags... flags) {
		return getFullDescription(flags).getDescription();
	}

	@Override
	public int compareTo(DebugRunningProcessImpl that) {
		int result;

		result = Integer.compare(this.systemId, that.systemId);
		if (result != 0) {
			return result;
		}

		return 0;
	}
}
