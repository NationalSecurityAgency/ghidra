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

import java.util.Set;

import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;

public class ObjectBasedDebuggerMappingOpinion implements DebuggerMappingOpinion {

	@Override
	public Set<DebuggerMappingOffer> getOffers(TargetObject target, boolean includeOverrides) {
		// TODO: Remove this check
		if (!includeOverrides) {
			return Set.of();
		}
		// TODO: Do I want to require it to record the whole model?
		// If not, I need to figure out how to locate object dependencies and still record them.
		if (!target.isRoot()) {
			return Set.of();
		}
		return Set.of(new ObjectBasedDebuggerMappingOffer(target));
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetObject target,
			boolean includeOverrides) {
		throw new UnsupportedOperationException();
	}
}
