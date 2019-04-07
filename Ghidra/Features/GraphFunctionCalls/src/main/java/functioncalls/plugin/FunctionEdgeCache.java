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
package functioncalls.plugin;

import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

import ghidra.program.model.listing.Function;

/**
 * A class to cache known function edges
 */
public class FunctionEdgeCache {

	/** Contains all known edges, even those not showing in the graph */
	private Map<Function, Set<FunctionEdge>> allEdgesByFunction =
		LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>());

	// note: having a function as a key in the above map is not enough to know if it has been
	//       processed already (as the function can be added by processing edges of other 
	//       nodes).  Being in this structure means that it has been processed for its 
	//       incoming and outgoing connections
	private Set<Function> tracked = new HashSet<>();

	public Set<FunctionEdge> get(Function f) {
		return allEdgesByFunction.get(f);
	}

	public boolean isTracked(Function f) {
		return tracked.contains(f);
	}

	public void setTracked(Function f) {
		tracked.add(f);
	}
}
