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
import ghidra.program.model.lang.Endian;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * An opinion governing selection of language and compiler spec when recording a target
 * 
 * <p>
 * When a target is recorded, the model service collects offers for the target and its environment
 * by querying all opinions discovered in the classpath. See
 * {@link #queryOpinions(TargetObject, boolean)}. If the recording was triggered automatically, the
 * highest-confidence offer is taken, so long as it is not an "override" offer. If triggered
 * manually, all offers are displayed for the user to choose from.
 * 
 * <p>
 * Override offers have negative confidence, and typically, one is only selected by the user as a
 * last-ditch effort when no opinion exists for the desired target. As such, one is never selected
 * automatically, and they are hidden from the manual record prompt by default.
 */
public interface DebuggerMappingOpinion extends ExtensionPoint {
	/**
	 * A comparator for sorting offers by decreasing confidence
	 */
	Comparator<DebuggerMappingOffer> HIGHEST_CONFIDENCE_FIRST =
		Comparator.comparing(o -> -o.getConfidence());

	/**
	 * Get the endianness from the given environment
	 * 
	 * @param env the target environment
	 * @return the endianness
	 */
	public static Endian getEndian(TargetEnvironment env) {
		String strEndian = env.getEndian();
		if (strEndian.contains("little")) {
			return Endian.LITTLE;
		}
		if (strEndian.contains("big")) {
			return Endian.BIG;
		}
		return null;
	}

	/**
	 * Query all known opinions for recording/tracing a debug session
	 * 
	 * <p>
	 * The returned offers are ordered highest-confidence first.
	 * 
	 * @param target the target to be recorded, usually a process
	 * @param includeOverrides true to include offers with negative confidence
	 * @return a future which completes with the set of offers
	 */
	public static List<DebuggerMappingOffer> queryOpinions(TargetObject target,
			boolean includeOverrides) {
		List<DebuggerMappingOffer> result = new ArrayList<>();
		for (DebuggerMappingOpinion opinion : ClassSearcher
				.getInstances(DebuggerMappingOpinion.class)) {
			try {
				Set<DebuggerMappingOffer> offers = opinion.getOffers(target, includeOverrides);
				synchronized (result) {
					result.addAll(offers);
				}
			}
			catch (Throwable t) {
				Msg.error(DebuggerMappingOpinion.class,
					"Problem querying opinion " + opinion + " for recording/mapping offers: " + t);
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
	public default Set<DebuggerMappingOffer> getOffers(TargetObject target,
			boolean includeOverrides) {
		if (!(target instanceof TargetProcess)) {
			return Set.of();
		}
		TargetProcess process = (TargetProcess) target;
		DebuggerObjectModel model = process.getModel();
		List<String> pathToEnv =
			model.getRootSchema().searchForSuitable(TargetEnvironment.class, process.getPath());
		if (pathToEnv == null) {
			Msg.error(this, "Could not find path to environment");
			return Set.of();
		}
		TargetEnvironment env = (TargetEnvironment) model.getModelObject(pathToEnv);
		return offersForEnv(env, process, includeOverrides);
	}

	/**
	 * Produce this opinion's offers for the given environment and target process
	 * 
	 * @param env the environment associated with the target
	 * @param process the target process
	 * @param includeOverrides true to include override offers, i.e., those with negative confidence
	 * @return the offers, possibly empty, but never null
	 */
	Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides);
}
