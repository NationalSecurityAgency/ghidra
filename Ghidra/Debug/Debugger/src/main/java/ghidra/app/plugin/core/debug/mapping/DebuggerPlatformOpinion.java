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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.util.PathPredicates;
import ghidra.program.model.lang.Endian;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * An opinion governing analysis and display of a trace according to a platform (processor, ISA, OS,
 * ABI, etc.)
 * 
 * <p>
 * This is meant for "object-based" traces, which may soon supplant "table-based" traces. The latter
 * requires mapping between the target model and the trace, and so the UI need not worry about
 * normalizing; however, without a mapping, nothing works. The former allows for direct recording of
 * the model into the trace without prior mapping. Instead, the choice of platform and
 * interpretation is performed by the front-end analysis and display. These are essentially the
 * counterpart to {@link DebuggerMappingOpinion}.
 * 
 * <p>
 * The opinions are queried, each of which may produce zero or more scored offers. Depending on
 * context and automation, the top offer may be chosen automatically, or the user may be prompted to
 * select from a sorted list. The chosen offer is then applied. Application here means writing
 * metadata to the trace database, usually as "guest platforms." The analysis and display use that
 * metadata to interpret the trace data, e.g., to select a language when disassembling at the
 * program counter.
 */
public interface DebuggerPlatformOpinion extends ExtensionPoint {

	Comparator<DebuggerPlatformOffer> HIGHEST_CONFIDENCE_FIRST =
		Comparator.comparing(o -> -o.getConfidence());

	/**
	 * Find the environment for the given object
	 * 
	 * @param object the object, usually the user's focus
	 * @param snap the current snap
	 * @return the environment object, or null
	 */
	static TraceObject getEnvironment(TraceObject object, long snap) {
		if (object == null) {
			return null;
		}
		TraceObject root = object.getRoot();
		List<String> pathToEnv = root.getTargetSchema()
				.searchForSuitable(TargetEnvironment.class, object.getCanonicalPath().getKeyList());
		if (pathToEnv == null) {
			return null;
		}
		return root.getSuccessors(Range.singleton(snap), PathPredicates.pattern(pathToEnv))
				.findAny()
				.map(p -> p.getDestination(root))
				.orElse(null);
	}

	static String getStringAttribute(TraceObject obj, long snap, String key) {
		TraceObjectValue val = obj.getValue(snap, key);
		if (val == null) {
			return null;
		}
		return val.getValue().toString();
	}

	static String getDebugggerFromEnv(TraceObject env, long snap) {
		return getStringAttribute(env, snap, TargetEnvironment.DEBUGGER_ATTRIBUTE_NAME);
	}

	static String getArchitectureFromEnv(TraceObject env, long snap) {
		return getStringAttribute(env, snap, TargetEnvironment.ARCH_ATTRIBUTE_NAME);
	}

	static String getOperatingSystemFromEnv(TraceObject env, long snap) {
		return getStringAttribute(env, snap, TargetEnvironment.OS_ATTRIBUTE_NAME);
	}

	/**
	 * Get the endianness from the given environment
	 * 
	 * @param env the environment object
	 * @param snap the current snap
	 * @return the endianness, or null
	 */
	static Endian getEndianFromEnv(TraceObject env, long snap) {
		String strEndian = getStringAttribute(env, snap, TargetEnvironment.ENDIAN_ATTRIBUTE_NAME);
		if (strEndian == null) {
			return null;
		}
		if (strEndian.toLowerCase().contains("little")) {
			return Endian.LITTLE;
		}
		if (strEndian.toLowerCase().contains("big")) {
			return Endian.BIG;
		}
		return null;
	}

	/**
	 * Query all known opinions for offers of platform interpretation
	 * 
	 * @param trace the trace
	 * @param object the object, usually the one in focus
	 * @param snap the snap
	 * @param includeOverrides true to include offers with negative confidence
	 * @return the list of offers ordered highest confidence first
	 */
	static List<DebuggerPlatformOffer> queryOpinions(Trace trace, TraceObject object, long snap,
			boolean includeOverrides) {
		List<DebuggerPlatformOffer> result = new ArrayList<>();
		for (DebuggerPlatformOpinion opinion : ClassSearcher
				.getInstances(DebuggerPlatformOpinion.class)) {
			try {
				Set<DebuggerPlatformOffer> offers =
					opinion.getOffers(trace, object, snap, includeOverrides);
				result.addAll(offers);
			}
			catch (Exception e) {
				Msg.error(DebuggerPlatformOpinion.class,
					"Problem querying opinion " + opinion + " for platform offers: " + e);
			}
		}
		result.sort(HIGHEST_CONFIDENCE_FIRST);
		return result;
	}

	/**
	 * Render offers for the given object
	 * 
	 * @param object the object, usually the one in focus
	 * @param includeOverrides true to include offers with negative confidence
	 * @return zero or more offers to interpret the target according to a platform
	 */
	Set<DebuggerPlatformOffer> getOffers(Trace trace, TraceObject object, long snap,
			boolean includeOverrides);
}
