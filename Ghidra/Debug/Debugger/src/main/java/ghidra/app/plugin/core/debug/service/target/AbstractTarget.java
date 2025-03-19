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
package ghidra.app.plugin.core.debug.service.target;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.function.Supplier;

import docking.ActionContext;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.TraceSpan;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractTarget implements Target {
	protected final PluginTool tool;

	public AbstractTarget(PluginTool tool) {
		this.tool = tool;
	}

	public PluginTool getTool() {
		return tool;
	}

	private Address staticToDynamicAddress(ProgramLocation location) {
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return null;
		}
		ProgramLocation dynLoc = mappingService
				.getDynamicLocationFromStatic(getTrace().getProgramView(), location);
		if (dynLoc == null) {
			return null;
		}
		return dynLoc.getByteAddress();
	}

	protected Address findAddress(Navigatable nav) {
		ProgramLocation location = nav.getLocation();
		if (location == null) {
			return null;
		}
		if (nav.isDynamic()) {
			return location.getAddress();
		}
		return staticToDynamicAddress(location);
	}

	protected Address findAddress(MarkerLocation location) {
		if (location.getProgram() instanceof TraceProgramView) {
			return location.getAddr();
		}
		return staticToDynamicAddress(
			new ProgramLocation(location.getProgram(), location.getAddr()));
	}

	protected Address findAddress(ActionContext context) {
		if (context instanceof NavigatableActionContext ctx) {
			Address address = findAddress(ctx.getNavigatable());
			if (address != null) {
				return address;
			}
		}
		if (context != null && context.getContextObject() instanceof MarkerLocation ml) {
			Address address = findAddress(ml);
			if (address != null) {
				return address;
			}
		}
		DebuggerListingService listingService = tool.getService(DebuggerListingService.class);
		if (listingService != null) {
			Address address = findAddress(listingService.getNavigatable());
			if (address != null) {
				return address;
			}
		}
		CodeViewerService codeViewerService = tool.getService(CodeViewerService.class);
		if (codeViewerService != null) {
			Address address = findAddress(codeViewerService.getNavigatable());
			if (address != null) {
				return address;
			}
		}
		return null;
	}

	protected AddressRange singleRange(AddressSetView set) {
		if (set == null || set.getNumAddressRanges() != 1) {
			return null;
		}
		return set.getFirstRange();
	}

	protected AddressRange findRange(Navigatable nav) {
		if (nav.isDynamic()) {
			return singleRange(nav.getSelection());
		}
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return null;
		}

		long snap = getSnap();
		AddressSet result = new AddressSet();
		Map<TraceSpan, Collection<MappedAddressRange>> mapped =
			mappingService.getOpenMappedViews(nav.getProgram(), nav.getSelection());
		for (Entry<TraceSpan, Collection<MappedAddressRange>> ent : mapped.entrySet()) {
			TraceSpan span = ent.getKey();
			if (span.getTrace() != getTrace() || span.getSpan().contains(snap)) {
				continue;
			}
			for (MappedAddressRange mar : ent.getValue()) {
				result.add(mar.getDestinationAddressRange());
			}
		}
		if (result.isEmpty()) {
			return null;
		}

		return singleRange(result);
	}

	protected AddressRange findRange(ActionContext context) {
		if (context instanceof NavigatableActionContext ctx) {
			AddressRange range = findRange(ctx.getNavigatable());
			if (range != null) {
				return range;
			}
		}
		DebuggerListingService listingService = tool.getService(DebuggerListingService.class);
		if (listingService != null) {
			AddressRange range = findRange(listingService.getNavigatable());
			if (range != null) {
				return range;
			}
		}
		CodeViewerService codeViewerService = tool.getService(CodeViewerService.class);
		if (codeViewerService != null) {
			AddressRange range = findRange(codeViewerService.getNavigatable());
			if (range != null) {
				return range;
			}
		}
		return null;
	}

	protected static <T> T doSync(String name, Supplier<CompletableFuture<T>> supplier)
			throws InterruptedException, ExecutionException {
		if (Swing.isSwingThread()) {
			throw new AssertionError("Cannot " + name + " using Swing thread. Use a Task.");
		}
		CompletableFuture<T> future = supplier.get();
		return future.orTimeout(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS).get();
	}

	protected static <T> T getSync(String name, Supplier<CompletableFuture<T>> supplier) {
		try {
			return doSync(name, supplier);
		}
		catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);
		}
	}

	protected static void runSync(String name, Supplier<CompletableFuture<Void>> supplier) {
		getSync(name, supplier);
	}

	protected static <T> T doSyncMonitored(TaskMonitor monitor, String name,
			Supplier<CompletableFuture<T>> supplier)
			throws CancelledException, InterruptedException, ExecutionException {
		monitor.checkCancelled();
		try {
			return doSync(name, supplier);
		}
		catch (ExecutionException e) {
			if (e.getCause() instanceof CancelledException ce) {
				throw ce;
			}
			throw e;
		}
	}

	protected static <T> T getSyncMonitored(TaskMonitor monitor, String name,
			Supplier<CompletableFuture<T>> supplier) throws CancelledException {
		try {
			return doSyncMonitored(monitor, name, supplier);
		}
		catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);
		}
	}

	protected static void runSyncMonitored(TaskMonitor monitor, String name,
			Supplier<CompletableFuture<Void>> supplier) throws CancelledException {
		getSyncMonitored(monitor, name, supplier);
	}

	@Override
	public String execute(String command, boolean toString) {
		return getSync("execute", () -> executeAsync(command, toString));
	}

	@Override
	public void activate(DebuggerCoordinates prev, DebuggerCoordinates coords) {
		runSync("activate", () -> activateAsync(prev, coords));
	}

	@Override
	public void invalidateMemoryCaches() {
		runSync("invalidate memory caches", () -> invalidateMemoryCachesAsync());
	}

	@Override
	public void readMemory(AddressSetView set, TaskMonitor monitor) throws CancelledException {
		runSyncMonitored(monitor, "read memory", () -> readMemoryAsync(set, monitor));
	}

	@Override
	public void writeMemory(Address address, byte[] data) {
		runSync("write memory", () -> writeMemoryAsync(address, data));
	}

	@Override
	public void readRegisters(TracePlatform platform, TraceThread thread,
			int frame, Set<Register> registers) {
		runSync("read registers",
			() -> readRegistersAsync(platform, thread, frame, registers));
	}

	@Override
	public CompletableFuture<Void> readRegistersAsync(TracePlatform platform, TraceThread thread,
			int frame, AddressSetView guestSet) {
		if (guestSet.isEmpty()) {
			return AsyncUtils.nil();
		}
		Set<Register> registers =
			TraceRegisterUtils.registersIntersecting(platform.getLanguage(), guestSet);
		return readRegistersAsync(platform, thread, frame, registers);
	}

	@Override
	public void readRegisters(TracePlatform platform, TraceThread thread,
			int frame, AddressSetView guestSet) {
		runSync("read registers",
			() -> readRegistersAsync(platform, thread, frame, guestSet));
	}

	@Override
	public void writeRegister(TracePlatform platform, TraceThread thread, int frame,
			RegisterValue value) {
		runSync("write register", () -> writeRegisterAsync(platform, thread, frame, value));
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform, TraceThread thread,
			int frame, Address address, byte[] data) {
		Register register = platform.getLanguage().getRegister(address, data.length);
		if (register == null) {
			throw new IllegalArgumentException(
				"Cannot identify the (single) register to write: " + address);
		}
		RegisterValue value = new RegisterValue(register,
			Utils.bytesToBigInteger(data, data.length, register.isBigEndian(), false));
		return writeRegisterAsync(platform, thread, frame, value);
	}

	@Override
	public void writeRegister(TracePlatform platform, TraceThread thread, int frame,
			Address address, byte[] data) {
		runSync("write register", () -> writeRegisterAsync(platform, thread, frame, address, data));
	}

	@Override
	public void writeVariable(TracePlatform platform, TraceThread thread, int frame,
			Address address, byte[] data) {
		runSync("write variable", () -> writeVariableAsync(platform, thread, frame, address, data));
	}

	@Override
	public void placeBreakpoint(AddressRange range, Set<TraceBreakpointKind> kinds,
			String condition, String commands) {
		runSync("place breakpoint", () -> placeBreakpointAsync(range, kinds, condition, commands));
	}

	@Override
	public void deleteBreakpoint(TraceBreakpoint breakpoint) {
		runSync("delete breakpoint", () -> deleteBreakpointAsync(breakpoint));
	}

	@Override
	public void toggleBreakpoint(TraceBreakpoint breakpoint, boolean enabled) {
		String msg = enabled ? "enable breakpoint" : "disable breakpoint";
		runSync(msg, () -> toggleBreakpointAsync(breakpoint, enabled));
	}

	@Override
	public void forceTerminate() {
		runSync("force terminate", () -> forceTerminateAsync());
	}

	@Override
	public void disconnect() {
		runSync("disconnect", this::disconnectAsync);
	}
}
