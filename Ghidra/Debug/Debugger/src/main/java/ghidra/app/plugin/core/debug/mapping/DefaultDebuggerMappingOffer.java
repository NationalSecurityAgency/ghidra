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
import java.util.Set;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.lang.*;

public class DefaultDebuggerMappingOffer implements DebuggerMappingOffer {
	protected final TargetObject target;
	protected final int confidence;
	protected final String description;
	protected final LanguageID langID;
	protected final CompilerSpecID csID;

	// TODO: Not sure this really belongs here....
	protected final Set<String> extraRegNames;

	public DefaultDebuggerMappingOffer(TargetObject target, int confidence,
			String description, LanguageID langID, CompilerSpecID csID,
			Collection<String> extraRegNames) {
		this.target = target;
		this.confidence = confidence;
		this.description = description;
		this.langID = langID;
		this.csID = csID;

		this.extraRegNames = Set.copyOf(extraRegNames);
	}

	@Override
	public String toString() {
		return String.format("<Offer: '%s' lang=%s cs=%s confidence=%d target=%s>", description,
			langID, csID, confidence, PathUtils.toString(target.getPath()));
	}

	@Override
	public int getConfidence() {
		return confidence;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public LanguageID getTraceLanguageID() {
		return langID;
	}

	@Override
	public CompilerSpecID getTraceCompilerSpecID() {
		return csID;
	}

	protected DebuggerTargetTraceMapper createMapper()
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		return new DefaultDebuggerTargetTraceMapper(target, langID, csID, extraRegNames);
	}

	@Override
	public DebuggerTargetTraceMapper take() {
		try {
			return createMapper();
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
			throw new AssertionError(e);
		}
	}
}
