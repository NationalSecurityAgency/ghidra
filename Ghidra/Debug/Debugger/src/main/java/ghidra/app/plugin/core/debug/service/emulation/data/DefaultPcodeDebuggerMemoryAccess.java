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
package ghidra.app.plugin.core.debug.service.emulation.data;

import java.util.Objects;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;

/**
 * The default data-and-debugger-access shim for session memory
 */
public class DefaultPcodeDebuggerMemoryAccess extends TranslatedPcodeDebuggerMemoryAccess {

	protected final ServiceProvider provider;

	/**
	 * Construct a shim
	 * 
	 * @param provider the service provider (usually the tool) to get the static mapping service
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerMemoryAccess(ServiceProvider provider, Target target,
			TracePlatform platform, long snap, TraceTimeViewport viewport) {
		super(target, platform, snap, viewport);
		this.provider = Objects.requireNonNull(provider);
	}

	@Override
	public DebuggerAddressTranslator getAddressTranslator() {
		return provider.getService(DebuggerStaticMappingService.class);
	}
}
