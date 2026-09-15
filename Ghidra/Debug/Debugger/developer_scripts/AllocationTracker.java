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
//EXPERIMENTAL script that tries to track memory allocations and frees in a trace.
//@category Debugger
//@keybinding
//@menupath
//@toolbar

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.modules.MappedAddressRange;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.trace.model.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;

public class AllocationTracker extends GhidraScript implements FlatDebuggerAPI {
	public record AllocFreeEvent(long snap, long size, Address allocedAddress,
			Address freedAddress,
			Function function, long returnStatus) {
	}

	public record EntryExitEvent(long snap, AllocOrFreeFunc allocOrFreeFunc, boolean entry) {
	}

	public record AllocatedBuffer(Lifespan lifespan, long size, Address startAddress) {
	}

	public static class AllocFreeEventBuilder {
		private long snap;
		private long size;
		private Address allocatedAddress;
		private Address freedAddress;
		private Function function;
		private boolean clear = true;
		private long returnStatus;

		public AllocFreeEventBuilder setSnap(long snap) {
			clear = false;
			this.snap = snap;
			return this;
		}

		public AllocFreeEventBuilder setSize(long size) {
			clear = false;
			this.size = size;
			return this;
		}

		public AllocFreeEventBuilder setAllocatedAddress(Address allocatedAddress) {
			clear = false;
			this.allocatedAddress = allocatedAddress;
			return this;
		}

		public AllocFreeEventBuilder setFreedAddress(Address freedAddress) {
			clear = false;
			this.freedAddress = freedAddress;
			return this;
		}

		public AllocFreeEventBuilder setReturnStatus(long returnStatus) {
			clear = false;
			this.returnStatus = returnStatus;
			return this;
		}

		public AllocFreeEventBuilder setFunction(Function function) {
			clear = false;
			this.function = function;
			return this;
		}

		public AllocFreeEvent createAllocFreeEvent() {
			AllocFreeEvent event =
					new AllocFreeEvent(snap, size, allocatedAddress, freedAddress, function,
							returnStatus);
			snap = 0;
			size = 0;
			returnStatus = 0;
			allocatedAddress = null;
			freedAddress = null;
			function = null;
			clear = true;
			return event;
		}

		public boolean isClear() {
			return clear;
		}
	}

	public class AllocFreePairings {
		private final List<AllocOrFreeFunc> funcs;

		AllocFreePairings(List<AllocOrFreeFunc> funcs) {
			this.funcs = funcs;
		}

		List<AllocFreeEvent> getAllEvents() {
			AddressSet addressSet = new AddressSet();
			funcs.forEach(e -> {
				addressSet.add(e.dynFunctionStart);
				addressSet.add(e.dynFunctionReturns);
			});

			return getCurrentTrace().getObjectManager()
					.getRootSchema()
					.getContext()
					.getAllSchemas()
					.stream()
					.filter(e -> e.getInterfaces().contains(TraceStackFrame.class))
					.map(s -> s.checkAliasedAttribute(TraceStackFrame.KEY_PC))
					.flatMap(path -> funcs.stream()
							.flatMap(func -> func.dynFunctionStartsAndReturns.stream()
									.flatMap(addrRange -> getCurrentTrace().getObjectManager()
											.getValuesIntersecting(Lifespan.ALL, addrRange, path)
											.stream()
											.sorted(Comparator.comparingLong(
													TraceObjectValue::getMinSnap))
											.map(tov -> {
												if (func.dynFunctionStart.intersects(addrRange)) {
													return new EntryExitEvent(tov.getMinSnap(),
															func, true);
												}
												else {
													return new EntryExitEvent(tov.getMinSnap(),
															func, false);
												}
											}))))
					.sorted(Comparator.comparingLong(EntryExitEvent::snap))
					.map(e -> {
						if (e.entry) {
							e.allocOrFreeFunc.onEntry(e.snap());
							return null;
						}
						else {
							return e.allocOrFreeFunc.onExit(e.snap());
						}
					})
					.filter(Objects::nonNull)
					.toList();
		}
	}

	class AllocOrFreeFunc {
		Function function;
		AddressSet functionStarts;
		AddressSet functionReturns;
		AddressSet dynFunctionStart;
		AddressSet dynFunctionReturns;
		AddressSet dynFunctionStartsAndReturns;
		AllocFreeEventBuilder allocFreeEventBuilder;

		AllocOrFreeFunc(Function function) {
			this.function = function;
			functionStarts = new AddressSet(function.getEntryPoint());
			functionReturns = new AddressSet();
			for (Instruction instruction : function.getProgram()
					.getListing()
					.getInstructions(function.getBody(), true)) {
				if (instruction.getFlowType().equals(RefType.TERMINATOR)) {
					functionReturns.add(instruction.getAddress());
				}
			}
			dynFunctionStart = getDynamicAddresses(functionStarts, function.getProgram());
			dynFunctionReturns = getDynamicAddresses(functionReturns, function.getProgram());
			dynFunctionStartsAndReturns = new AddressSet();
			dynFunctionStartsAndReturns.add(dynFunctionStart);
			dynFunctionStartsAndReturns.add(dynFunctionReturns);
			allocFreeEventBuilder = new AllocFreeEventBuilder();

		}

		AddressSet getDynamicAddresses(AddressSet staticSet, Program program) {
			final DebuggerStaticMappingService staticMappingService =
					state.getTool().getService(DebuggerStaticMappingService.class);
			final AddressSet dynamicSet = new AddressSet();

			for (AddressRange address : staticSet) {
				Map<TraceSpan, Collection<MappedAddressRange>> openMappedViews =
						staticMappingService.getOpenMappedViews(program, new AddressSet(address));
				for (Map.Entry<TraceSpan, Collection<MappedAddressRange>> entry :
						openMappedViews.entrySet()) {
					if (entry.getKey().getTrace() != getCurrentTrace()) {
						continue;
					}
					for (MappedAddressRange addressRange : entry.getValue()) {
						dynamicSet.add(addressRange.getDestinationAddressRange().getMinAddress(),
								addressRange.getDestinationAddressRange().getMaxAddress());
					}
				}
			}
			return dynamicSet;
		}

		BigInteger getVariableValue(Variable variable, long snap) {
			Trace trace = getCurrentTrace();
			Address address = variable.getMinAddress();
			final ByteBuffer buf = ByteBuffer.allocate(variable.getLength());
			TraceThread eventThread =
					trace.getTimeManager().getSnapshot(snap, false).getEventThread();
			if (address.isStackAddress()) {
				final CompilerSpec spec = trace.getBaseCompilerSpec();

				final RegisterValue value = trace.getMemoryManager()
						.getMemoryRegisterSpace(eventThread, false)
						.getValue(snap, spec.getStackPointer());

				final Address stackPointer =
						spec.getStackBaseSpace().getAddress(value.getUnsignedValue().longValue());

				address = stackPointer.add(address.getOffset());
				trace.getMemoryManager().getBytes(snap, address, buf);
			}
			else if (address.isMemoryAddress()) {
				trace.getMemoryManager().getBytes(snap, address, buf);
			}
			else if (address.isRegisterAddress()) {
				final RegisterValue regVal = trace.getMemoryManager()
						.getMemoryRegisterSpace(eventThread, false)
						.getValue(snap, variable.getRegister());
				return regVal.getUnsignedValue();
			}

			byte[] bytes = new byte[buf.remaining()];
			buf.get(bytes);
			return new BigInteger(bytes);
		}

		void onEntry(long snap) {
			if (!allocFreeEventBuilder.isClear()) {
				printerr("Seems like we missed a function exit for %s".formatted(function));
			}
		}

		AllocFreeEvent onExit(long snap) {
			return allocFreeEventBuilder.createAllocFreeEvent();
		}
	}

	class malloc extends AllocOrFreeFunc {
		malloc(Function function) {
			super(function);
		}

		@Override
		void onEntry(long snap) {
			super.onEntry(snap);
			allocFreeEventBuilder.setSize(
							getVariableValue(function.getParameter(0), snap).longValue())
					.setFunction(function)
					.setSnap(snap);
		}

		@Override
		AllocFreeEvent onExit(long snap) {
			allocFreeEventBuilder.setAllocatedAddress(
							toAddr(getVariableValue(function.getReturn(), snap).longValue()))
					.setFunction(function);
			return super.onExit(snap);
		}
	}

	class calloc extends AllocOrFreeFunc {
		calloc(Function function) {
			super(function);
		}

		@Override
		void onEntry(long snap) {
			super.onEntry(snap);
			allocFreeEventBuilder.setSize(
							getVariableValue(function.getParameter(0), snap).longValue() *
							getVariableValue(function.getParameter(1), snap).longValue())
					.setFunction(function)
					.setSnap(snap);
		}

		@Override
		AllocFreeEvent onExit(long snap) {
			allocFreeEventBuilder.setAllocatedAddress(
							toAddr(getVariableValue(function.getReturn(), snap).longValue()))
					.setFunction(function);

			return super.onExit(snap);
		}
	}

	class realloc extends AllocOrFreeFunc {
		realloc(Function function) {
			super(function);
		}

		@Override
		void onEntry(long snap) {
			super.onEntry(snap);
			allocFreeEventBuilder.setFreedAddress(
							toAddr(getVariableValue(function.getParameter(0), snap).longValue()))
					.setSize(getVariableValue(function.getParameter(1), snap).longValue())
					.setFunction(function)
					.setSnap(snap);
		}

		@Override
		AllocFreeEvent onExit(long snap) {
			allocFreeEventBuilder.setAllocatedAddress(
							toAddr(getVariableValue(function.getReturn(), snap).longValue()))
					.setFunction(function);

			return super.onExit(snap);
		}
	}

	class free extends AllocOrFreeFunc {
		free(Function function) {
			super(function);
		}

		@Override
		void onEntry(long snap) {
			super.onEntry(snap);
			allocFreeEventBuilder.setFreedAddress(
							toAddr(getVariableValue(function.getParameter(0), snap).longValue()))
					.setFunction(function)
					.setSnap(snap);
		}

//		@Override
//		AllocFreeEvent onExit(long snap) {
//			allocFreeEventBuilder.setReturnStatus(
//					getVariableValue(function.getReturn(), snap).longValue());
//			return super.onExit(snap);
//		}
	}

	@Override
	protected void run() throws Exception {
		AllocFreePairings pairing = new AllocFreePairings(
				List.of(new malloc(getMatchingFunction("malloc")),
						new calloc(getMatchingFunction("calloc")),
						new realloc(getMatchingFunction("realloc")),
						new free(getMatchingFunction("free"))));

		Map<Address, AllocFreeEvent> allocationTracker = new HashMap<>();
		List<AllocatedBuffer> allocatedBuffers = new ArrayList<>();

		for (AllocFreeEvent event : pairing.getAllEvents()) {
			if (event.freedAddress != null) {
				if (!allocationTracker.containsKey(event.freedAddress)) {
					println("Double free?? %x".formatted(event.freedAddress.getUnsignedOffset()));
				}
				else {
					AllocFreeEvent allocEvent = allocationTracker.get(event.freedAddress);
					allocatedBuffers.add(
							new AllocatedBuffer(Lifespan.span(allocEvent.snap, event.snap),
									allocEvent.size(), allocEvent.allocedAddress));
					allocationTracker.remove(event.freedAddress);
				}
			}
			if (event.allocedAddress != null) {
				if (allocationTracker.containsKey(event.allocedAddress)) {
					println("Did we miss a free?? %x".formatted(
							event.allocedAddress.getUnsignedOffset()));
				}
				else {
					allocationTracker.put(event.allocedAddress, event);
				}
			}
		}

		println("Unfreed memory: %s".formatted(allocationTracker.keySet()));
		println("Allocated buffers: %s".formatted(allocatedBuffers));
	}

	public Function getMatchingFunction(String funcName) {
		for (Program program : state.getTool()
				.getService(ProgramManager.class)
				.getAllOpenPrograms()) {
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				if (!f.isThunk() && !f.isExternal() && funcName.equals(f.getName().toLowerCase())) {
					return f;
				}
			}
		}
		return null;
	}
}
