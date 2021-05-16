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

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

public interface DebuggerMappingOpinion extends ExtensionPoint {
	Comparator<DebuggerMappingOffer> HIGHEST_CONFIDENCE_FIRST =
		Comparator.comparing(o -> -o.getConfidence());

	/**
	 * Query all known opinions for recording/tracing a debug session
	 * 
	 * <p>
	 * The returned offers are ordered highest-confidence first.
	 * 
	 * @param target the target to be recorded, usually a process
	 * @return a future which completes with the set of offers
	 */
	public static List<DebuggerMappingOffer> queryOpinions(TargetObject target) {
		List<DebuggerMappingOffer> result = new ArrayList<>();
		for (DebuggerMappingOpinion opinion : ClassSearcher
				.getInstances(DebuggerMappingOpinion.class)) {
			try {
				Set<DebuggerMappingOffer> offers = opinion.getOffers(target);
				synchronized (result) {
					result.addAll(offers);
				}
			}
			catch (Throwable t) {
				Msg.error(DebuggerMappingOpinion.class,
					"Problem querying opinion " + opinion + " for recording/mapping offers");
			}
		}
		result.sort(HIGHEST_CONFIDENCE_FIRST);
		return result;
	}

	/**
	 * Checks if this opinion knows how to handle the given target
	 * 
	 * @param target the target, usually a process
	 * @return a future which completes with true if it knows, false if not
	 */
	public default Set<DebuggerMappingOffer> getOffers(TargetObject target) {
		if (!(target instanceof TargetProcess)) {
			return Set.of();
		}
		TargetProcess process = (TargetProcess) target;
		DebuggerObjectModel model = process.getModel();
		List<String> pathToEnv =
			model.getRootSchema().searchForSuitable(TargetEnvironment.class, process.getPath());
		TargetEnvironment env = (TargetEnvironment) model.getModelObject(pathToEnv);
		return offersForEnv(env, process);
	}

	Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process);

}
