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

import ghidra.program.model.lang.Endian;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public abstract class AbstractDebuggerPlatformOpinion implements DebuggerPlatformOpinion {

	protected abstract Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap,
			TraceObject env, String debugger, String arch, String os, Endian endian,
			boolean includeOverrides);

	@Override
	public Set<DebuggerPlatformOffer> getOffers(Trace trace, TraceObject object, long snap,
			boolean includeOverrides) {
		TraceObject env = DebuggerPlatformOpinion.getEnvironment(object, snap);
		if (env == null) {
			return getOffers(object, snap, env, null, null, null, null, includeOverrides);
		}
		String debugger = DebuggerPlatformOpinion.getDebugggerFromEnv(env, snap);
		String arch = DebuggerPlatformOpinion.getArchitectureFromEnv(env, snap);
		String os = DebuggerPlatformOpinion.getOperatingSystemFromEnv(env, snap);
		Endian endian = DebuggerPlatformOpinion.getEndianFromEnv(env, snap);
		return getOffers(object, snap, env, debugger, arch, os, endian, includeOverrides);
	}
}
