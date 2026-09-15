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
package dap;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.eclipse.lsp4j.debug.*;
import org.eclipse.lsp4j.debug.StackFrame;
import org.eclipse.lsp4j.debug.services.IDebugProtocolClient;
import org.eclipse.lsp4j.debug.services.IDebugProtocolServer;

import docking.ActionContext;
import ghidra.app.plugin.core.debug.gui.action.BasicAutoReadMemorySpec;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget;
import ghidra.app.services.*;
import ghidra.debug.api.model.DebuggerSingleObjectPathActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.target.Target.ObjectArgumentPolicy;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.CommonSet;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.thread.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class DapDebugAdapter implements IDebugProtocolServer {

	private DapPlugin plugin;
	private DebuggerTraceManagerService manager;
	private TraceRmiService rmi;
	private DebuggerStaticMappingService mappings;

	private Trace trace;
	private TraceRmiTarget target;
	private TraceRmiConnection conn;
	private RemoteMethodRegistry registry;

	private Map<String, DataBreakpointInfo> dataBreakpoints = new HashMap<>();
	private AddressSpace space;
	private IDebugProtocolClient client;

	public DapDebugAdapter(DapPlugin plugin, PluginTool tool) {
		this.plugin = plugin;
		this.manager = tool.getService(DebuggerTraceManagerService.class);
		this.rmi = tool.getService(TraceRmiService.class);
		this.mappings = tool.getService(DebuggerStaticMappingService.class);
		setCoordinates(manager.getCurrentFor(manager.getCurrentTrace()));
	}

	public void setCoordinates(DebuggerCoordinates coordinates) {
		Trace traceFromCoord = coordinates.getTrace();
		if (traceFromCoord == null || traceFromCoord.equals(this.trace)) {
			return;
		}
		this.trace = traceFromCoord;
		this.target = (TraceRmiTarget) coordinates.getTarget();

		space = trace.getBaseAddressFactory().getDefaultAddressSpace();
		for (TraceRmiConnection c : rmi.getAllConnections()) {
			if (c.getTargets().contains(target)) {
				this.conn = c;
				break;
			}
		}
		this.registry = conn.getMethods();
		plugin.addListener(trace);
	}

	@Override
	public CompletableFuture<Capabilities> initialize(InitializeRequestArguments args) {
		Capabilities capabilities = new Capabilities();
		capabilities.setSupportsConfigurationDoneRequest(true);
		//capabilities.setSupportsConditionalBreakpoints(true);
		capabilities.setSupportsDataBreakpoints(true);
		capabilities.setSupportsDataBreakpointBytes(true);
		capabilities.setSupportsFunctionBreakpoints(true);
		capabilities.setSupportsInstructionBreakpoints(true);
		capabilities.setSupportsModulesRequest(true);
		capabilities.setSupportsReadMemoryRequest(true);
		capabilities.setSupportsWriteMemoryRequest(true);
		capabilities.setSupportsTerminateRequest(true);
		capabilities.setSupportsDisassembleRequest(true);
		client.initialized();
		return CompletableFuture.completedFuture(capabilities);
	}

	@Override
	public CompletableFuture<Void> disconnect(DisconnectArguments args) {
		plugin.removeListener(trace);
		this.trace = null;
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<ContinueResponse> continue_(ContinueArguments args) {
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		ActionContext context =
			new DebuggerSingleObjectPathActionContext(thread.getObject().getCanonicalPath());
		return invoke(ActionName.RESUME, context).thenApply(_ -> {
			ContinueResponse response = new ContinueResponse();
			response.setAllThreadsContinued(true);
			return response;
		});
	}

	@Override
	public CompletableFuture<Void> reverseContinue(ReverseContinueArguments args) {
		// TODO: We should standardize this
		RemoteMethod method0 = registry.get("go_back");
		RemoteMethod method1 = registry.get("resume_back");
		if (method0 == null && method1 == null) {
			return CompletableFuture.failedFuture(
				new UnsupportedOperationException(
					"The connected backend does not support the 'reverse continue' method."));
		}

		RemoteMethod method = method0 == null ? method1 : method0;
		return method.invokeAsync(new HashMap<>()).toCompletableFuture().thenApply(_ -> null);
	}

	@Override
	public CompletableFuture<Void> next(NextArguments args) {
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		ActionContext context =
			new DebuggerSingleObjectPathActionContext(thread.getObject().getCanonicalPath());
		return invoke(ActionName.STEP_OVER, context);
	}

	@Override
	public CompletableFuture<Void> stepIn(StepInArguments args) {
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		ActionContext context =
			new DebuggerSingleObjectPathActionContext(thread.getObject().getCanonicalPath());
		return invoke(ActionName.STEP_INTO, context);
	}

	@Override
	public CompletableFuture<Void> stepOut(StepOutArguments args) {
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		ActionContext context =
			new DebuggerSingleObjectPathActionContext(thread.getObject().getCanonicalPath());
		return invoke(ActionName.STEP_OUT, context);
	}

	@Override
	public CompletableFuture<Void> stepBack(StepBackArguments args) {
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		ActionContext context =
			new DebuggerSingleObjectPathActionContext(thread.getObject().getCanonicalPath());
		return invoke(ActionName.STEP_BACK, context);
	}

	@Override
	public CompletableFuture<Void> pause(PauseArguments args) {
		TraceProcess proc = getProcess();
		ActionContext context =
			new DebuggerSingleObjectPathActionContext(proc.getObject().getCanonicalPath());
		return invoke(ActionName.INTERRUPT, context);
	}

	@Override
	public CompletableFuture<SetInstructionBreakpointsResponse> setInstructionBreakpoints(
			SetInstructionBreakpointsArguments args) {
		return clearExistingBreakpointsOfType(false)
				.thenCompose(_ -> {
					List<CompletableFuture<Void>> futuresList = new ArrayList<>();
					InstructionBreakpoint[] breakpoints = args.getBreakpoints();
					for (InstructionBreakpoint bpt : breakpoints) {
						String ref = bpt.getInstructionReference();
						TraceBreakpointKindSet kind = kind(bpt.getMode());
						String condition = bpt.getCondition();
						try {
							Address address = space.getAddress(ref).add(bpt.getOffset());
							CompletableFuture<Void> future = target.placeBreakpointAsync(
								new AddressRangeImpl(address, 1), kind, condition, null);
							futuresList.add(future);
						}
						catch (Exception e) {
							// Drop malformed entries (excluded entries in the response
							// should be apparent to the client)
						}
					}
					return CompletableFuture.allOf(futuresList.toArray(new CompletableFuture[0]));
				})
				.thenApply(_ -> {
					List<Breakpoint> rbpts = getBreakpointList();
					SetInstructionBreakpointsResponse response =
						new SetInstructionBreakpointsResponse();
					response.setBreakpoints(rbpts.toArray(new Breakpoint[0]));
					return response;
				});
	}

	public record DataBreakpointInfo(String key, String mode, int size) {}

	@Override
	public CompletableFuture<DataBreakpointInfoResponse> dataBreakpointInfo(
			DataBreakpointInfoArguments args) {
		Boolean asAddress = args.getAsAddress();
		Integer size = args.getBytes();
		String mode = args.getMode();
		String name = args.getName();

		if (asAddress == null || !asAddress) {
			return CompletableFuture.completedFuture(null);
		}

		dataBreakpoints.put(name, new DataBreakpointInfo(name, mode, size != null ? size : 1));

		DataBreakpointInfoResponse response = new DataBreakpointInfoResponse();
		response.setDescription(name);
		response.setDataId(name);
		response.setAccessTypes(DataBreakpointAccessType.values());
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<SetBreakpointsResponse> setBreakpoints(SetBreakpointsArguments args) {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active program source file trace map."));
		}
		return clearExistingBreakpointsOfType(false)
				.thenCompose(_ -> {
					List<CompletableFuture<Void>> futuresList = new ArrayList<>();
					convertAndPlaceBreakpoints(args, program, futuresList);
					return CompletableFuture.allOf(futuresList.toArray(new CompletableFuture[0]));
				})
				.thenApply(_ -> {
					List<Breakpoint> rbpts = getBreakpointList();
					SetBreakpointsResponse response = new SetBreakpointsResponse();
					response.setBreakpoints(rbpts.toArray(new Breakpoint[0]));
					return response;
				});
	}

	private void convertAndPlaceBreakpoints(SetBreakpointsArguments args, Program program,
			List<CompletableFuture<Void>> futuresList) {
		SourceFileManager sourceManager = program.getSourceFileManager();
		SourceBreakpoint[] breakpoints = args.getBreakpoints();
		for (SourceBreakpoint bpt : breakpoints) {
			int ref = bpt.getLine();
			List<SourceFile> files = sourceManager.getMappedSourceFiles();
			for (SourceFile f : files) {
				List<SourceMapEntry> entries =
					sourceManager.getSourceMapEntries(f, ref);
				for (SourceMapEntry entry : entries) {
					convertAndPlaceBreakpoint(program, futuresList, bpt, entry);
				}
			}
		}
	}

	private void convertAndPlaceBreakpoint(Program program,
			List<CompletableFuture<Void>> futuresList,
			SourceBreakpoint bpt, SourceMapEntry entry) {
		try {
			Address baseAddress = entry.getBaseAddress();
			Address targetAddress = dynamicForStatic(program, baseAddress);
			if (targetAddress != null) {
				CompletableFuture<Void> future = target.placeBreakpointAsync(
					new AddressRangeImpl(targetAddress, 1),
					kind(bpt.getMode()),
					bpt.getCondition(), null);
				futuresList.add(future);
			}
		}
		catch (Exception e) {
			// Drop malformed entries 
		}
	}

	@Override
	public CompletableFuture<SetDataBreakpointsResponse> setDataBreakpoints(
			SetDataBreakpointsArguments args) {
		return clearExistingBreakpointsOfType(true)
				.thenCompose(_ -> {
					List<CompletableFuture<Void>> futuresList = new ArrayList<>();
					DataBreakpoint[] breakpoints = args.getBreakpoints();
					for (DataBreakpoint bpt : breakpoints) {
						String ref = bpt.getDataId();
						DataBreakpointInfo info = dataBreakpoints.get(ref);
						DataBreakpointAccessType accessType = bpt.getAccessType();
						String condition = bpt.getCondition();

						try {
							Address address = space.getAddress(ref);
							CompletableFuture<Void> future = target.placeBreakpointAsync(
								new AddressRangeImpl(address, info.size()), kinds(accessType),
								condition, null);
							futuresList.add(future);
						}
						catch (Exception e) {
							// Drop malformed entries 
						}
					}
					return CompletableFuture.allOf(futuresList.toArray(new CompletableFuture[0]));
				})
				.thenApply(_ -> {
					List<Breakpoint> rbpts = getBreakpointList();
					SetDataBreakpointsResponse response = new SetDataBreakpointsResponse();
					response.setBreakpoints(rbpts.toArray(new Breakpoint[0]));
					return response;
				});
	}

	@Override
	public CompletableFuture<SetFunctionBreakpointsResponse> setFunctionBreakpoints(
			SetFunctionBreakpointsArguments args) {
		return clearExistingBreakpointsOfType(false)
				.thenCompose(_ -> {
					List<CompletableFuture<Void>> futuresList = new ArrayList<>();
					FunctionBreakpoint[] breakpoints = args.getBreakpoints();
					for (FunctionBreakpoint bpt : breakpoints) {
						Function f = getFunctionByName(bpt.getName());
						if (f == null) {
							continue;
						}
						Address targetAddress = dynamicForStatic(f.getProgram(), f.getEntryPoint());
						if (targetAddress == null) {
							continue;
						}
						try {
							CompletableFuture<Void> future = target.placeBreakpointAsync(
								new AddressRangeImpl(targetAddress, 1),
								CommonSet.SWX.kinds(),
								bpt.getCondition(), null);
							futuresList.add(future);
							break;
						}
						catch (Exception e) {
							// Drop malformed entries 
						}
					}
					return CompletableFuture.allOf(futuresList.toArray(new CompletableFuture[0]));
				})
				.thenApply(_ -> {
					List<Breakpoint> rbpts = getBreakpointList();
					SetFunctionBreakpointsResponse response =
						new SetFunctionBreakpointsResponse();
					response.setBreakpoints(rbpts.toArray(new Breakpoint[0]));
					return response;
				});
	}

	private CompletableFuture<Void> clearExistingBreakpointsOfType(boolean dataBreakpoints) {
		// TODO: Do we really want to do this?
		//  Right now, it's not obvious that the DAP client knows about all breakpoints, i.e. 
		//  unclear whether it receives/filters client.breakpoint messages. Until it does, seems
		//  unwise to clear breakpoints possible only know to Ghidra
		List<CompletableFuture<Void>> deletionFutures = new ArrayList<>();
		return CompletableFuture.allOf(deletionFutures.toArray(new CompletableFuture[0]));
	}

	private Function getFunctionByName(String name) {
		Program program = plugin.getCurrentProgram();
		if (program == null || name == null) {
			return null;
		}
		SymbolIterator symbols = program.getSymbolTable().getSymbols(name);
		while (symbols.hasNext()) {
			Symbol sym = symbols.next();
			if (sym.getObject() instanceof Function func) {
				return func;
			}
		}
		return null;
	}

	private Address dynamicForStatic(Program program, Address staticAddress) {
		ProgramLocation dynamicLocation = mappings.getDynamicLocationFromStatic(
			trace.getProgramView(), new ProgramLocation(program, staticAddress));
		return dynamicLocation == null ? null : dynamicLocation.getAddress();
	}

	@Override
	public CompletableFuture<StackTraceResponse> stackTrace(StackTraceArguments args) {
		Integer startFrame = args.getStartFrame();
		Integer levels = args.getLevels();
		int tid = args.getThreadId();
		// TOOO: StackFrameFormat format = args.getFormat();

		TraceThread thread = getThread(tid);
		if (thread == null || thread.getObject() == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("No active thread context found."));
		}

		long currentSnap = manager.getCurrentSnap();
		TraceStack stack = trace.getStackManager().getLatestStack(thread, currentSnap);
		if (stack == null) {
			return CompletableFuture.completedFuture(new StackTraceResponse());
		}

		StackTraceResponse response = new StackTraceResponse();
		List<StackFrame> rframes = new ArrayList<>();
		int start = (startFrame != null) ? startFrame : 0;
		int maxLevels = (levels != null && levels > 0) ? levels : stack.getDepth(currentSnap);

		for (TraceStackFrame f : stack.getFrames(currentSnap)) {
			if (f.getLevel() >= start && rframes.size() < maxLevels) {
				StackFrame rf = new StackFrame();
				rf.setId(f.getLevel());

				String desc = getDisplay(f.getObject());
				if (desc != null) {
					rf.setName(desc);
				}

				rf.setInstructionPointerReference(
					f.getProgramCounter(currentSnap).toString());
				rframes.add(rf);
			}
		}
		response.setStackFrames(rframes.toArray(new StackFrame[0]));
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<ThreadsResponse> threads() {
		if (trace == null) {
			return CompletableFuture.completedFuture(null);
		}

		TraceThreadManager threadManager = trace.getThreadManager();
		Collection<? extends TraceThread> threads =
			threadManager.getLiveThreads(manager.getCurrentSnap());

		ThreadsResponse response = new ThreadsResponse();
		List<org.eclipse.lsp4j.debug.Thread> rthreads = new ArrayList<>();

		for (TraceThread t : threads) {
			org.eclipse.lsp4j.debug.Thread rt = new org.eclipse.lsp4j.debug.Thread();
			rt.setId(getThreadId(t));
			rt.setName(t.getName(manager.getCurrentSnap()));
			rthreads.add(rt);
		}
		response.setThreads(rthreads.toArray(new org.eclipse.lsp4j.debug.Thread[0]));
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<ModulesResponse> modules(ModulesArguments args) {
		if (trace == null) {
			return CompletableFuture.completedFuture(null);
		}

		TraceModuleManager modManager = trace.getModuleManager();
		Collection<? extends TraceModule> modules =
			modManager.getLoadedModules(manager.getCurrentSnap());

		ModulesResponse response = new ModulesResponse();
		List<org.eclipse.lsp4j.debug.Module> rmods = new ArrayList<>();

		for (TraceModule m : modules) {
			org.eclipse.lsp4j.debug.Module rm = new org.eclipse.lsp4j.debug.Module();
			rm.setId((int) m.getObject().getKey());
			rm.setName(m.getName(manager.getCurrentSnap()));
			rm.setAddressRange(m.getRange(manager.getCurrentSnap()).toString());
			rmods.add(rm);
		}
		response.setModules(rmods.toArray(new org.eclipse.lsp4j.debug.Module[0]));
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<EvaluateResponse> evaluate(EvaluateArguments args) {
		return target.executeAsync(args.getExpression(), true)
				.toCompletableFuture()
				.thenApply(result -> {
					EvaluateResponse response = new EvaluateResponse();
					response.setResult(result != null ? result.toString() : "null");
					return response;
				});
	}

	@Override
	public CompletableFuture<Void> terminate(TerminateArguments args) {
		return target.disconnectAsync();
	}

	@Override
	public CompletableFuture<ReadMemoryResponse> readMemory(ReadMemoryArguments args) {
		Address baseAddress = getAddress(args.getMemoryReference());
		int requestedCount = args.getCount();
		long offsetAdjustment = (args.getOffset() != null) ? args.getOffset() : 0L;

		final Address address;
		try {
			address = baseAddress.add(offsetAdjustment);
		}
		catch (AddressOutOfBoundsException e) {
			return CompletableFuture.failedFuture(e);
		}

		AddressSetView view;
		try {
			view = new AddressSet(address, address.add(requestedCount - 1));
		}
		catch (AddressOutOfBoundsException e) {
			return CompletableFuture.failedFuture(e);
		}

		return BasicAutoReadMemorySpec.VISIBLE
				.readMemory(plugin.getTool(), manager.getCurrentFor(trace), view)
				.thenApply(_ -> {
					ByteBuffer buf = ByteBuffer.allocate(args.getCount());
					int bytesRead =
						trace.getMemoryManager()
								.getViewBytes(manager.getCurrentSnap(), address, buf);
					buf.flip();

					ReadMemoryResponse response = new ReadMemoryResponse();
					response.setAddress(address.toString());
					String data =
						new String(Base64.getEncoder().encode(buf).limit(bytesRead).array());
					response.setData(data);
					response.setUnreadableBytes(args.getCount() - bytesRead);
					return response;
				});
	}

	@Override
	public CompletableFuture<WriteMemoryResponse> writeMemory(WriteMemoryArguments args) {
		Address baseAddress = getAddress(args.getMemoryReference());
		long offsetAdjustment = (args.getOffset() != null) ? args.getOffset() : 0L;

		final Address address;
		try {
			address = baseAddress.add(offsetAdjustment);
		}
		catch (AddressOutOfBoundsException e) {
			return CompletableFuture.failedFuture(e);
		}

		byte[] bytes = Base64.getDecoder().decode(args.getData());
		return target.writeMemoryAsync(address, bytes).thenApply(_ -> {
			WriteMemoryResponse response = new WriteMemoryResponse();
			response.setOffset(args.getOffset());
			response.setBytesWritten(bytes.length);
			return response;
		});
	}

	@Override
	public CompletableFuture<LoadedSourcesResponse> loadedSources(LoadedSourcesArguments args) {
		SourceFileManager sourceManager = plugin.getCurrentProgram().getSourceFileManager();
		List<SourceFile> mappedSourceFiles = sourceManager.getMappedSourceFiles();
		LoadedSourcesResponse response = new LoadedSourcesResponse();
		List<Source> sources = new ArrayList<>();

		for (SourceFile f : mappedSourceFiles) {
			Source src = new Source();
			src.setName(f.getFilename());
			src.setPath(f.getPath());
			sources.add(src);
		}
		response.setSources(sources.toArray(new Source[0]));
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<DisassembleResponse> disassemble(DisassembleArguments args) {
		Listing listing = trace.getProgramView().getListing();
		String memoryReference = args.getMemoryReference();
		Address start = getAddress(memoryReference);
		int count = args.getInstructionCount();
		InstructionIterator iter = listing.getInstructions(start, true);
		List<Instruction> instructions = new ArrayList<>();
		while (iter.hasNext() && instructions.size() < count) {
			instructions.add(iter.next());
		}

		DisassembleResponse response = new DisassembleResponse();
		DisassembledInstruction[] rinstructions = new DisassembledInstruction[instructions.size()];
		int n = 0;
		for (Instruction i : instructions) {
			DisassembledInstruction ri = new DisassembledInstruction();
			ri.setAddress(i.getAddress().toString());
			ri.setInstruction(i.toString());
			try {
				String rep = NumericUtilities.convertBytesToString(i.getBytes(), ":");
				ri.setInstructionBytes(rep);
			}
			catch (MemoryAccessException e) {
				Msg.error(this, e.getMessage());
			}
			rinstructions[n++] = ri;
		}
		response.setInstructions(rinstructions);
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<Void> goto_(GotoArguments args) {
		TracePlatform platform = trace.getPlatformManager().getHostPlatform();
		TraceThread thread = getThread(args.getThreadId());
		if (thread == null) {
			return CompletableFuture.failedFuture(
				new IllegalStateException("Thread missing during context update."));
		}
		Register pc = trace.getBaseLanguage().getProgramCounter();
		RegisterValue rval = new RegisterValue(pc, BigInteger.valueOf(args.getTargetId()));
		return target.writeRegisterAsync(platform, thread, 0, rval);
	}

	// NOT CURRENTLY IMPLEMENTED

	@Override
	public CompletableFuture<Void> launch(Map<String, Object> args) {
		RemoteMethod method = registry.get("launch");
		if (method == null) {
			return CompletableFuture.failedFuture(
				new UnsupportedOperationException(
					"The connected backend does not support the 'launch' method."));
		}

		return method.invokeAsync(args).toCompletableFuture().thenApply(_ -> null);
	}

	@Override
	public CompletableFuture<Void> attach(Map<String, Object> args) {
		RemoteMethod method = registry.get("attach");
		if (method == null) {
			return CompletableFuture.completedFuture(null);
		}

		return method.invokeAsync(args).toCompletableFuture().thenApply(_ -> null);
	}

	@Override
	public CompletableFuture<Void> restart(RestartArguments args) {
		RemoteMethod method = registry.get("launch");
		if (method == null) {
			return CompletableFuture.failedFuture(
				new UnsupportedOperationException(
					"The connected backend does not support the 'restart' method."));
		}

		return method.invokeAsync(new HashMap<>()).toCompletableFuture().thenApply(_ -> null);
	}

	@Override
	public CompletableFuture<ExceptionInfoResponse> exceptionInfo(ExceptionInfoArguments args) {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<SetExceptionBreakpointsResponse> setExceptionBreakpoints(
			SetExceptionBreakpointsArguments args) {
		return CompletableFuture.completedFuture(null);
	}

	// private methods

	private CompletableFuture<Void> invoke(ActionName action, ActionContext context) {
		ActionEntry entry = target
				.collectActions(action, context,
					ObjectArgumentPolicy.CURRENT_AND_RELATED)
				.values()
				.stream()
				.filter(e -> !e.requiresPrompt())
				.sorted(Comparator.comparing(e -> -e.specificity()))
				.findFirst()
				.orElse(null);
		if (entry != null) {
			return entry.invokeAsyncWithoutTimeout(false).thenApply(_ -> null);
		}
		return CompletableFuture.failedFuture(new RuntimeException("No such method"));
	}

	public int getThreadId(TraceThread thread) {
		var tidAttr = thread.getObject().getValue(manager.getCurrentSnap(), TraceThread.KEY_TID);
		if (tidAttr == null || tidAttr.getValue() == null) {
			return -1;
		}

		Long tid = (Long) tidAttr.getValue();
		return tid.intValue();
	}

	TraceProcess getProcess() {
		TraceThread currentThread = manager.getCurrentThread();
		if (currentThread == null) {
			return null;
		}
		return currentThread.getObject()
				.queryAncestorsInterface(Lifespan.ALL, TraceProcess.class)
				.findFirst()
				.orElse(null);
	}

	private TraceThread getThread(int threadId) {
		for (TraceThread t : trace.getThreadManager().getAllThreads()) {
			int tid = getThreadId(t);
			if (tid == threadId) {
				return t;
			}
		}
		return manager.getCurrentThread();
	}

	private TraceBreakpointKindSet kind(String mode) {
		return mode.equals("hardware") ? CommonSet.HWX.kinds() : CommonSet.SWX.kinds();
	}

	private TraceBreakpointKindSet kinds(DataBreakpointAccessType accessType) {
		return switch (accessType) {
			case DataBreakpointAccessType.READ -> CommonSet.READ.kinds();
			case DataBreakpointAccessType.WRITE -> CommonSet.WRITE.kinds();
			case DataBreakpointAccessType.READ_WRITE -> CommonSet.ACCESS.kinds();
			case null -> CommonSet.SWX.kinds();
			default -> CommonSet.SWX.kinds();
		};
	}

	List<Breakpoint> getBreakpointList() {
		List<Breakpoint> rbpts = new ArrayList<>();
		if (trace == null) {
			return rbpts;
		}

		Collection<? extends TraceBreakpointLocation> bpts =
			trace.getBreakpointManager().getAllBreakpointLocations();
		for (TraceBreakpointLocation loc : bpts) {
			AddressRange range = loc.getRange(manager.getCurrentSnap());
			if (range == null) {
				continue;
			}
			String key = loc.getName(manager.getCurrentSnap());
			key = key.substring(1, key.indexOf("]"));

			Breakpoint rbpt = new Breakpoint();
			rbpt.setId(Integer.parseInt(key));
			rbpt.setInstructionReference(range.getMinAddress().toString(false));
			//rbpt.setOffset(0);
			rbpt.setVerified(true);
			rbpts.add(rbpt);
		}
		return rbpts;
	}

	private Address getAddress(String offset) {
		if (offset == null || space == null) {
			return null;
		}

		try {
			return space.getAddress(offset);
		}
		catch (AddressFormatException e) {
			return null;
		}
	}

	private String getDisplay(TraceObject obj) {
		if (obj == null) {
			return "UNKNOWN";
		}
		var displayAttr = obj.getValue(manager.getCurrentSnap(), TraceObjectInterface.KEY_DISPLAY);
		if (displayAttr == null || displayAttr.getValue() == null) {
			return "UNKNOWN";
		}
		Object display = displayAttr.getValue();
		if (display instanceof String desc) {
			return desc;
		}
		return display.toString();
	}

//	private int getLine(Address address) {
//		SourceFileManager sourceManager = plugin.getCurrentProgram().getSourceFileManager();
//		List<SourceMapEntry> sourceMapEntries = sourceManager.getSourceMapEntries(address);
//		for (SourceMapEntry entry : sourceMapEntries) {
//			return entry.getLineNumber();
//		}
//		return -1;
//	}
//
//	private String getFile(Address address) {
//		SourceFileManager sourceManager = plugin.getCurrentProgram().getSourceFileManager();
//		List<SourceMapEntry> sourceMapEntries = sourceManager.getSourceMapEntries(address);
//		for (SourceMapEntry entry : sourceMapEntries) {
//			return entry.getSourceFile().getFilename();
//		}
//		return "";
//	}

	public void setClient(IDebugProtocolClient client) {
		this.client = client;

		StoppedEventArguments args = new StoppedEventArguments();
		args.setAllThreadsStopped(true);
		args.setReason("initialization");
		client.stopped(args);
	}

	public IDebugProtocolClient getClient() {
		return this.client;
	}

	// UNSUPPORTED but called enough we'd rather not throw an exception

	@Override
	public CompletableFuture<Void> configurationDone(ConfigurationDoneArguments args) {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<ScopesResponse> scopes(ScopesArguments args) {
		ScopesResponse response = new ScopesResponse();
		return CompletableFuture.completedFuture(response);
	}

	@Override
	public CompletableFuture<VariablesResponse> variables(VariablesArguments args) {
		return CompletableFuture.completedFuture(null);
	}
}
