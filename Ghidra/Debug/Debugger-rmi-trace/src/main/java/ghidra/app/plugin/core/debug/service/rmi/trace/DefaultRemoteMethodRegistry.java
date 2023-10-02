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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import java.util.*;

import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.*;

public class DefaultRemoteMethodRegistry implements RemoteMethodRegistry {
	private final Map<String, RemoteMethod> map = new HashMap<>();
	private final Map<ActionName, Set<RemoteMethod>> byAction = new HashMap<>();

	protected void add(RemoteMethod method) {
		synchronized (map) {
			map.put(method.name(), method);
			byAction.computeIfAbsent(method.action(), k -> new HashSet<>()).add(method);
		}
	}

	@Override
	public Map<String, RemoteMethod> all() {
		synchronized (map) {
			return Map.copyOf(map);
		}
	}

	@Override
	public RemoteMethod get(String name) {
		synchronized (map) {
			return map.get(name);
		}
	}

	@Override
	public Set<RemoteMethod> getByAction(ActionName action) {
		synchronized (map) {
			return byAction.getOrDefault(action, Set.of());
		}
	}
}
