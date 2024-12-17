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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.Transaction;
import ghidra.app.services.DebuggerTargetService;
import ghidra.async.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;

public abstract class TestTraceRmiConnection extends AbstractTraceRmiConnection {

	protected final TestRemoteMethodRegistry registry = new TestRemoteMethodRegistry();
	protected final CompletableFuture<Trace> firstTrace = new CompletableFuture<>();
	protected final Map<Trace, TraceSnapshot> snapshots = new HashMap<>();
	protected final CompletableFuture<Void> closed = new CompletableFuture<>();
	protected final Map<Trace, TraceRmiTarget> targets = new HashMap<>();

	public static class TestRemoteMethodRegistry extends DefaultRemoteMethodRegistry {
		@Override
		public void add(RemoteMethod method) {
			super.add(method);
		}
	}

	public record TestRemoteMethod(String name, ActionName action, String display,
			String description, Map<String, RemoteParameter> parameters, SchemaName retType,
			AsyncPairingQueue<Map<String, Object>> argQueue, AsyncPairingQueue<Object> retQueue)
			implements RemoteMethod {
		public TestRemoteMethod(String name, ActionName action, String display, String description,
				Map<String, RemoteParameter> parameters, SchemaName retType) {
			this(name, action, display, description, parameters, retType, new AsyncPairingQueue<>(),
				new AsyncPairingQueue<>());
		}

		public TestRemoteMethod(String name, ActionName action, String display, String description,
				SchemaName retType, RemoteParameter... parameters) {
			this(name, action, display, description, Stream.of(parameters)
					.collect(Collectors.toMap(RemoteParameter::name, p -> p)),
				retType);
		}

		public TestRemoteMethod(String name, ActionName action, String display, String description,
				Map<String, RemoteParameter> parameters, TargetObjectSchema retType) {
			this(name, action, display, description, parameters, retType.getName(),
				new AsyncPairingQueue<>(), new AsyncPairingQueue<>());
		}

		public TestRemoteMethod(String name, ActionName action, String display, String description,
				TargetObjectSchema retType, RemoteParameter... parameters) {
			this(name, action, display, description, Stream.of(parameters)
					.collect(Collectors.toMap(RemoteParameter::name, p -> p)),
				retType);
		}

		@Override
		public RemoteAsyncResult invokeAsync(Map<String, Object> arguments) {
			argQueue.give().complete(arguments);
			DefaultRemoteAsyncResult result = new DefaultRemoteAsyncResult();
			retQueue.take().handle(AsyncUtils.copyTo(result));
			return result;
		}

		public Map<String, Object> expect()
				throws InterruptedException, ExecutionException, TimeoutException {
			return argQueue.take().get(AsyncTestUtils.TIMEOUT_MS, TimeUnit.MILLISECONDS);
		}

		public void result(Object ret) {
			retQueue.give().complete(ret);
		}

		public CompletableFuture<Map<String, Object>> expect(
				Function<Map<String, Object>, Object> impl) {
			record ArgsRet(Map<String, Object> args, Object ret) {}
			var result = argQueue().take().thenApply(a -> new ArgsRet(a, impl.apply(a)));
			result.thenApply(ar -> ar.ret).handle(AsyncUtils.copyTo(retQueue().give()));
			return result.thenApply(ar -> ar.args);
		}
	}

	public record TestRemoteParameter(String name, SchemaName type, boolean required,
			Object defaultValue, String display, String description) implements RemoteParameter {
		public TestRemoteParameter(String name, TargetObjectSchema type, boolean required,
				Object defaultValue, String display, String description) {
			this(name, type.getName(), required, defaultValue, display, description);
		}

		@Override
		public Object getDefaultValue() {
			return defaultValue;
		}
	}

	@Override
	public String getDescription() {
		return "Test Trace RMI connnection";
	}

	@Override
	public SocketAddress getRemoteAddress() {
		return new InetSocketAddress("localhost", 0);
	}

	@Override
	public TestRemoteMethodRegistry getMethods() {
		return registry;
	}

	public void injectTrace(Trace trace) {
		firstTrace.complete(trace);
	}

	public TraceRmiTarget publishTarget(PluginTool tool, Trace trace) {
		injectTrace(trace);
		TraceRmiTarget target = new TraceRmiTarget(tool, this, trace);
		synchronized (targets) {
			targets.put(trace, target);
		}
		DebuggerTargetService targetService = tool.getService(DebuggerTargetService.class);
		targetService.publishTarget(target);
		return target;
	}

	public void withdrawTarget(PluginTool tool, Trace trace) {
		Target target;
		synchronized (targets) {
			target = targets.remove(trace);
		}
		DebuggerTargetService targetService = tool.getService(DebuggerTargetService.class);
		targetService.withdrawTarget(target);
	}

	@Override
	public Trace waitForTrace(long timeoutMillis) throws TimeoutException {
		try {
			return firstTrace.get(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException | ExecutionException e) {
			throw new AssertionError(e);
		}
	}

	public TraceSnapshot setLastSnapshot(Trace trace, long snap) {
		synchronized (snapshots) {
			try (Transaction tx = trace.openTransaction("Add snapshot")) {
				TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, true);
				snapshots.put(trace, snapshot);
				return snapshot;
			}
		}
	}

	@Override
	public long getLastSnapshot(Trace trace) {
		synchronized (snapshots) {
			TraceSnapshot snap = snapshots.get(trace);
			return snap == null ? 0 : snap.getKey();
		}
	}

	@Override
	public void forceCloseTrace(Trace trace) {
		TraceRmiTarget target;
		synchronized (targets) {
			target = targets.remove(trace);
		}
		DebuggerTargetService targetService =
			target.getTool().getService(DebuggerTargetService.class);
		targetService.withdrawTarget(target);
	}

	@Override
	public boolean isTarget(Trace trace) {
		synchronized (this.targets) {
			return targets.containsKey(trace);
		}
	}

	@Override
	public void close() throws IOException {
		Set<TraceRmiTarget> targets;
		synchronized (this.targets) {
			targets = new HashSet<>(this.targets.values());
			this.targets.clear();
		}
		for (TraceRmiTarget target : targets) {
			DebuggerTargetService targetService =
				target.getTool().getService(DebuggerTargetService.class);
			targetService.withdrawTarget(target);
		}
		closed.complete(null);
	}

	@Override
	public boolean isClosed() {
		return closed.isDone();
	}

	@Override
	public void waitClosed() {
		try {
			closed.get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public Collection<Target> getTargets() {
		return List.copyOf(targets.values());
	}

	@Override
	protected boolean ownsTrace(Trace trace) {
		return targets.containsKey(trace);
	}

	public void synthActivate(TraceObject object) {
		Trace trace = object.getTrace();
		doActivate(object, trace, snapshots.get(trace));
	}
}
