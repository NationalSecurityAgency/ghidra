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

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

public interface DebuggerMappingOffer {
	/**
	 * Get the first offer from the collection which successfully yields a mapper.
	 * 
	 * <p>
	 * Manual overrides are excluded.
	 * 
	 * @param offers the collection of offers, usually ordered by highest confidence first
	 * @return the first mapper from the offers, or {@code null} if there are no offers, or none
	 *         yield a mapper
	 */
	static DebuggerTargetTraceMapper first(Collection<DebuggerMappingOffer> offers) {
		for (DebuggerMappingOffer offer : offers) {
			if (offer.isOverride()) {
				continue;
			}
			try {
				DebuggerTargetTraceMapper mapper = offer.take();
				Msg.info(DebuggerMappingOffer.class, "Selected first mapping offer: " + offer);
				return mapper;
			}
			catch (Throwable t) {
				Msg.error(DebuggerMappingOffer.class,
					"Offer " + offer + " failed to take. Trying next.");
			}
		}
		return null;
	}

	/**
	 * Get the single offer from the collection that is not a manual override.
	 * 
	 * @param offers the collection of offers
	 * @return the offer or {@code null} if more than one non-override offer is present
	 */
	static DebuggerMappingOffer unique(Collection<DebuggerMappingOffer> offers) {
		List<DebuggerMappingOffer> filt =
			offers.stream().filter(o -> !o.isOverride()).collect(Collectors.toList());
		if (filt.size() != 1) {
			return null;
		}
		return filt.get(0);
	}

	/**
	 * Get the confidence of this offer.
	 * 
	 * <p>
	 * Offers with numerically higher confidence are preferred. Negative confidence values are
	 * considered "manual overrides," and so are never selected automatically and are hidden from
	 * prompts by default.
	 * 
	 * <p>
	 * TODO: Spec out some standard numbers. Maybe an enum?
	 * 
	 * @return the confidence
	 */
	int getConfidence();

	/**
	 * Check if the confidence indicates this offer is a manual override.
	 * 
	 * @return true if the confidence is negative
	 */
	default boolean isOverride() {
		return getConfidence() < 0;
	}

	/**
	 * Get a human-readable description of the offer.
	 * 
	 * <p>
	 * Generally, more detailed descriptions imply a higher confidence.
	 * 
	 * @return the description
	 */
	String getDescription();

	/**
	 * Get the language id for the destination trace.
	 * 
	 * @return the language id
	 */
	LanguageID getTraceLanguageID();

	/**
	 * Get the compiler spec id for the destination trace.
	 * 
	 * @return the compiler spec id
	 */
	CompilerSpecID getTraceCompilerSpecID();

	/**
	 * Get the mapper which implements this offer
	 * 
	 * @return the mapper
	 */
	DebuggerTargetTraceMapper take();
}
