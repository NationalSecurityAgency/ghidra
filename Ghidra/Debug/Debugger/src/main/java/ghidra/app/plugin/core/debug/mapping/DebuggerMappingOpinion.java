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
package ghidra.app.plugin.core.debug.mapping;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetObject;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

public interface DebuggerMappingOpinion extends ExtensionPoint {
	Comparator<DebuggerMappingOffer> HIGHEST_CONFIDENCE_FIRST =
		Comparator.comparing(o -> -o.getConfidence());

	/**
	 * Query all known opinions for recording/tracing a debug session
	 * 
	 * The returned offers are ordered highest-confidence first.
	 * 
	 * @param target the target to be recorded, usually a process
	 * @return a future which completes with the set of offers
	 */
	public static CompletableFuture<List<DebuggerMappingOffer>> queryOpinions(
			TargetObject target) {
		List<DebuggerMappingOffer> result = new ArrayList<>();
		AsyncFence fence = new AsyncFence();
		for (DebuggerMappingOpinion opinion : ClassSearcher
				.getInstances(DebuggerMappingOpinion.class)) {
			fence.include(opinion.getOffers(target).thenAccept(offers -> {
				synchronized (result) {
					result.addAll(offers);
				}
			}));
		}
		return fence.ready().thenApply(__ -> {
			result.sort(HIGHEST_CONFIDENCE_FIRST);
			return result;
		});
	}

	/**
	 * Checks if this opinion knows how to handle the given target
	 * 
	 * @param target the target, usually a process
	 * @return a future which completes with true if it knows, false if not
	 */
	CompletableFuture<Set<DebuggerMappingOffer>> getOffers(TargetObject target);
}
