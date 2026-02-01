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

import java.util.concurrent.CompletableFuture;

import ghidra.debug.api.emulation.PcodeDebuggerRegistersAccess;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceRegistersAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * The default data-and-debugger access shim for session registers
 */
public class DefaultPcodeDebuggerRegistersAccess extends DefaultPcodeTraceRegistersAccess
		implements PcodeDebuggerRegistersAccess, InternalPcodeDebuggerDataAccess {

	protected final ServiceProvider provider;
	protected final Target target;

	/**
	 * Construct a shim
	 * 
	 * @param provider the service provider (usually the tool)
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param thread the associated thread whose registers to access
	 * @param frame the associated frame, or 0 if not applicable
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerRegistersAccess(ServiceProvider provider, Target target,
			TracePlatform platform, long snap, TraceThread thread, int frame,
			TraceTimeViewport viewport) {
		super(platform, snap, thread, frame, viewport);
		this.provider = provider;
		this.target = target;
	}

	@Override
	public boolean isLive() {
		return InternalPcodeDebuggerDataAccess.super.isLive();
	}

	@Override
	public ServiceProvider getServiceProvider() {
		return provider;
	}

	@Override
	public Target getTarget() {
		return target;
	}

	@Override
	public CompletableFuture<Boolean> readFromTargetRegisters(AddressSetView guestView) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		return target.readRegistersAsync(platform, thread, frame, guestView).thenApply(__ -> true);
	}

	@Override
	public CompletableFuture<Boolean> writeTargetRegister(Address address, byte[] data) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		return target.writeRegisterAsync(platform, thread, frame, address, data)
				.thenApply(__ -> true);
	}

	// No need to override getPropertyAccess. Registers are not static mapped.
}
