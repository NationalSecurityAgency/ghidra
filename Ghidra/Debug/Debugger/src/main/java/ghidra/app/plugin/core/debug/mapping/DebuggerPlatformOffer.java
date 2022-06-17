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

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.Trace;

/**
 * An offer to map from a trace to a Ghidra langauge / compiler
 */
public interface DebuggerPlatformOffer {

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
	 * Get the language to which this offer can map
	 * 
	 * @return the langauge
	 */
	default Language getLanguage() {
		CompilerSpec cSpec = getCompilerSpec();
		return cSpec == null ? null : cSpec.getLanguage();
	}

	/**
	 * Get the compiler to which this offer can map
	 * 
	 * @return the compiler spec
	 */
	CompilerSpec getCompilerSpec();

	default CompilerSpec getCompilerSpec(LanguageID langID, CompilerSpecID cSpecID) {
		try {
			LanguageService langServ = DefaultLanguageService.getLanguageService();
			Language lang = langServ.getLanguage(langID);
			return cSpecID == null ? lang.getDefaultCompilerSpec()
					: lang.getCompilerSpecByID(cSpecID);
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Get the mapper, which implements this offer
	 * 
	 * @param tool the plugin tool
	 * @param trace the trace the trace to be mapped
	 * @return the mapper
	 */
	DebuggerPlatformMapper take(PluginTool tool, Trace trace);
}
