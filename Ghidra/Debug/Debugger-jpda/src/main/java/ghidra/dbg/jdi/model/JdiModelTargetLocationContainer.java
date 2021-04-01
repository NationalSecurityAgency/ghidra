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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.Location;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "LocationContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetLocation.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetLocationContainer extends JdiModelTargetObjectImpl {

	private List<Location> locations;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetLocation> locationsByName = new HashMap<>();

	public JdiModelTargetLocationContainer(JdiModelTargetObject parent, String name,
			List<Location> locations) {
		super(parent, name);
		this.locations = locations;
	}

	protected CompletableFuture<Void> updateUsingLocations(Map<String, Location> byName) {
		List<JdiModelTargetLocation> locs;
		synchronized (this) {
			locs =
				byName.values().stream().map(this::getTargetLocation).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetLocation loc : locs) {
			fence.include(loc.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), locs, Map.of(), "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, Location> map = new HashMap<>();
		if (locations != null) {
			for (Location loc : locations) {
				map.put(loc.toString(), loc);
			}
		}
		locationsByName.keySet().retainAll(map.keySet());
		return updateUsingLocations(map);
	}

	protected synchronized JdiModelTargetLocation getTargetLocation(Location loc) {
		return locationsByName.computeIfAbsent(loc.toString(),
			n -> new JdiModelTargetLocation(this, loc, true));
	}

	public synchronized JdiModelTargetLocation getTargetLocationsIfPresent(String name) {
		return locationsByName.get(name);
	}
}
