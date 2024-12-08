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
package ghidra.app.plugin.core.debug.service.control;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import docking.ActionContext;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MockTarget implements Target {
	private final Trace trace;
	private long snap = 0;

	public MockTarget(Trace trace) {
		this.trace = trace;
	}

	@Override
	public String describe() {
		return "Mock Target";
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	public void setSnap(long snap) {
		this.snap = snap;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	@Override
	public Map<String, ActionEntry> collectActions(ActionName name, ActionContext context) {
		return Map.of();
	}

	@Override
	public TraceThread getThreadForSuccessor(TraceObjectKeyPath path) {
		return null;
	}

	@Override
	public TargetExecutionState getThreadExecutionState(TraceThread thread) {
		return null;
	}

	@Override
	public TraceStackFrame getStackFrameForSuccessor(TraceObjectKeyPath path) {
		return null;
	}

	@Override
	public boolean isSupportsFocus() {
		return false;
	}

	@Override
	public TraceObjectKeyPath getFocus() {
		return null;
	}

	@Override
	public CompletableFuture<Void> activateAsync(DebuggerCoordinates prev,
			DebuggerCoordinates coords) {
		return AsyncUtils.nil();
	}

	@Override
	public void activate(DebuggerCoordinates prev, DebuggerCoordinates coords) {
	}

	@Override
	public CompletableFuture<Void> invalidateMemoryCachesAsync() {
		return AsyncUtils.nil();
	}

	@Override
	public void invalidateMemoryCaches() {
	}

	@Override
	public CompletableFuture<String> executeAsync(String command, boolean toString) {
		return AsyncUtils.nil();
	}

	@Override
	public String execute(String command, boolean toString) {
		return null;
	}

	@Override
	public CompletableFuture<Void> readMemoryAsync(AddressSetView set, TaskMonitor monitor) {
		return AsyncUtils.nil();
	}

	@Override
	public void readMemory(AddressSetView set, TaskMonitor monitor) throws CancelledException {
	}

	@Override
	public CompletableFuture<Void> writeMemoryAsync(Address address, byte[] data) {
		return AsyncUtils.nil();
	}

	@Override
	public void writeMemory(Address address, byte[] data) {
	}

	@Override
	public CompletableFuture<Void> readRegistersAsync(TracePlatform platform,
			TraceThread thread, int frame, Set<Register> registers) {
		return AsyncUtils.nil();
	}

	@Override
	public void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			Set<Register> registers) {
	}

	@Override
	public CompletableFuture<Void> readRegistersAsync(TracePlatform platform,
			TraceThread thread, int frame, AddressSetView guestSet) {
		return AsyncUtils.nil();
	}

	@Override
	public void readRegisters(TracePlatform platform, TraceThread thread, int frame,
			AddressSetView guestSet) {
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform,
			TraceThread thread, int frame, RegisterValue value) {
		return AsyncUtils.nil();
	}

	@Override
	public void writeRegister(TracePlatform platform, TraceThread thread, int frame,
			RegisterValue value) {
	}

	@Override
	public CompletableFuture<Void> writeRegisterAsync(TracePlatform platform,
			TraceThread thread, int frame, Address address, byte[] data) {
		return AsyncUtils.nil();
	}

	@Override
	public void writeRegister(TracePlatform platform, TraceThread thread, int frame,
			Address address, byte[] data) {
	}

	@Override
	public boolean isVariableExists(TracePlatform platform, TraceThread thread, int frame,
			Address address, int length) {
		return false;
	}

	@Override
	public CompletableFuture<Void> writeVariableAsync(TracePlatform platform,
			TraceThread thread, int frame, Address address, byte[] data) {
		return AsyncUtils.nil();
	}

	@Override
	public void writeVariable(TracePlatform platform, TraceThread thread, int frame,
			Address address, byte[] data) {
	}

	@Override
	public Set<TraceBreakpointKind> getSupportedBreakpointKinds() {
		return Set.of();
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAsync(AddressRange range,
			Set<TraceBreakpointKind> kinds, String condition, String commands) {
		return AsyncUtils.nil();
	}

	@Override
	public void placeBreakpoint(AddressRange range, Set<TraceBreakpointKind> kinds,
			String condition, String commands) {
	}

	@Override
	public boolean isBreakpointValid(TraceBreakpoint breakpoint) {
		return true;
	}

	@Override
	public CompletableFuture<Void> deleteBreakpointAsync(TraceBreakpoint breakpoint) {
		return AsyncUtils.nil();
	}

	@Override
	public void deleteBreakpoint(TraceBreakpoint breakpoint) {
	}

	@Override
	public CompletableFuture<Void> toggleBreakpointAsync(TraceBreakpoint breakpoint,
			boolean enabled) {
		return AsyncUtils.nil();
	}

	@Override
	public void toggleBreakpoint(TraceBreakpoint breakpoint, boolean enabled) {
	}

	@Override
	public CompletableFuture<Void> forceTerminateAsync() {
		return AsyncUtils.nil();
	}

	@Override
	public void forceTerminate() {
	}

	@Override
	public CompletableFuture<Void> disconnectAsync() {
		return AsyncUtils.nil();
	}

	@Override
	public void disconnect() {
	}
}
