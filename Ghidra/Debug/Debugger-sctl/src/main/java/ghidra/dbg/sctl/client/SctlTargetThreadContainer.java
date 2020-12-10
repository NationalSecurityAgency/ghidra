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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.util.PathUtils;

public class SctlTargetThreadContainer
		extends DefaultTargetObject<SctlTargetThread, SctlTargetProcess> {

	protected final SctlClient client;

	private final Map<Long, SctlTargetThread> threadsByCtlid = new LinkedHashMap<>();

	public SctlTargetThreadContainer(SctlTargetProcess process) {
		super(process.client, process, "Threads", "ThreadContainer");
		this.client = process.client;
	}

	protected void put(long ctlid, SctlTargetThread newThread, String reason) {
		synchronized (this) {
			threadsByCtlid.put(ctlid, newThread);
			client.session.processes.putThread(ctlid, newThread);
		}
		changeElements(List.of(), List.of(newThread), reason);
	}

	protected synchronized SctlTargetThread getByCtlid(long ctlid) {
		return threadsByCtlid.get(ctlid);
	}

	protected SctlTargetThread removeByCtlid(long ctlid, String reason) {
		SctlTargetThread removed;
		synchronized (this) {
			removed = threadsByCtlid.remove(ctlid);
			client.session.processes.removeThread(ctlid);
		}
		if (removed != null) {
			changeElements(List.of(PathUtils.makeIndex(ctlid)), List.of(), reason);
		}
		return removed;
	}

	protected void removeOthers(SctlTargetThread but, String reason) {
		Set<String> others = threadsByCtlid.keySet()
				.stream()
				.map(PathUtils::makeIndex)
				.filter(i -> i != but.getIndex())
				.collect(Collectors.toSet());
		changeElements(others, List.of(), reason);
	}
}
