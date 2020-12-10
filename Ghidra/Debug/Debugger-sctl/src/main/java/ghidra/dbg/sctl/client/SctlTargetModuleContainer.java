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
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;

public class SctlTargetModuleContainer
		extends DefaultTargetObject<SctlTargetModule, SctlTargetProcess> {

	protected final SctlClient client;

	private final Map<Long, SctlTargetModule> modulesByNsid = new LinkedHashMap<>();

	public SctlTargetModuleContainer(SctlTargetProcess process) {
		super(process.client, process, "Modules", "ModuleContainer");
		this.client = process.client;
	}

	/**
	 * Create a module proxy
	 * 
	 * This is preferred to calling {@link SctlTargetModule(SctlClient, long, String, boolean)}
	 * directly, since this will add the module to the client's container.
	 * 
	 * @param nsid the SCTL-assigned NSID "namespace ID"
	 * @param filepath the path given in {@code Tnames}
	 * @param executable the module is the executable image defining this process
	 * @return the new module proxy
	 */
	@Internal
	public SctlTargetModule create(long nsid, String filepath, Address base, boolean executable) {
		SctlTargetModule ns =
			new SctlTargetModule(this, nsid, filepath, base, executable);
		client.session.processes.putModule(nsid, ns);
		modulesByNsid.put(nsid, ns);
		changeElements(List.of(), List.of(ns), "Refreshed");
		return ns;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (refresh) {
			parent.lazyStat.forget();
		}
		return parent.lazyStat.request();
	}

	protected void clear() {
		// TODO: For refreshing, would rather collect and the use setElements
		synchronized (this) {
			client.session.processes.removeAllModules(modulesByNsid);
			modulesByNsid.clear();
		}
		setElements(List.of(), "Refreshing");
	}

	protected String getExecutablePath() {
		for (SctlTargetModule module : modulesByNsid.values()) {
			if (module.executable) {
				return module.filepath;
			}
		}
		return null;
	}
}
