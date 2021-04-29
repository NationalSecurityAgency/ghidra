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

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

public interface DebuggerMappingOffer {
	static DebuggerTargetTraceMapper first(Collection<DebuggerMappingOffer> offers) {
		for (DebuggerMappingOffer offer : offers) {
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

	// TODO: Spec out some standard numbers. Maybe an enum?
	int getConfidence();

	String getDescription();

	LanguageID getTraceLanguageID();

	CompilerSpecID getTraceCompilerSpecID();

	DebuggerTargetTraceMapper take();
}
