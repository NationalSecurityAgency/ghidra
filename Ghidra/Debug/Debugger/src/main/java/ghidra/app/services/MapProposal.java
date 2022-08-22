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
package ghidra.app.services;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.util.task.TaskMonitor;

public interface MapProposal<T, P, E extends MapEntry<T, P>> {
	/**
	 * Flatten proposals into a single collection of entries
	 * 
	 * <p>
	 * The output is suitable for use in
	 * {@link DebuggerStaticMappingService#addMappings(Collection, TaskMonitor, boolean, String)}.
	 * In some contexts, the user should be permitted to see and optionally adjust the collection
	 * first.
	 * 
	 * <p>
	 * Note, it is advisable to filter the returned collection using
	 * {@link #removeOverlapping(Collection)} to avoid errors from adding overlapped mappings.
	 * Alternatively, you can set {@code truncateExisting} to true when calling
	 * {@link DebuggerStaticMappingService#addMappings(Collection, TaskMonitor, boolean, String)}.
	 * 
	 * @param proposals the collection of proposed maps
	 * @return the flattened, filtered collection
	 */
	static <T, P, E extends MapEntry<T, P>, M extends MapProposal<T, P, E>> Collection<E> flatten(
			Collection<M> proposals) {
		Collection<E> result = new LinkedHashSet<>();
		for (M map : proposals) {
			result.addAll(map.computeMap().values());
		}
		return result;
	}

	/**
	 * Remove entries from a collection which overlap existing entries in the trace
	 * 
	 * @param entries the entries to filter
	 * @return the filtered entries
	 */
	static <E extends MapEntry<?, ?>> Set<E> removeOverlapping(Collection<E> entries) {
		return entries.stream().filter(e -> {
			TraceStaticMappingManager manager = e.getFromTrace().getStaticMappingManager();
			return manager.findAllOverlapping(e.getFromRange(), e.getFromLifespan()).isEmpty();
		}).collect(Collectors.toSet());
	}

	/**
	 * Get the trace containing the trace objects in this proposal
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the corresponding program image of this proposal
	 * 
	 * @return the program
	 */
	Program getProgram();

	/**
	 * Get the destination (program) object for a given source (trace) object
	 * 
	 * @param from the trace object
	 * @return the proposed program object
	 */
	P getToObject(T from);

	/**
	 * Compute a notional "score" of the proposal
	 * 
	 * <p>
	 * This may examine attributes of the "from" and "to" objects, in order to determine the
	 * likelihood of the match based on this proposal. The implementation need not assign meaning to
	 * any particular score, but a higher score must imply a more likely match.
	 * 
	 * @return a score of the proposed pair
	 */
	double computeScore();

	/**
	 * Compute the overall map given by this proposal
	 * 
	 * @return the map
	 */
	Map<T, E> computeMap();
}
