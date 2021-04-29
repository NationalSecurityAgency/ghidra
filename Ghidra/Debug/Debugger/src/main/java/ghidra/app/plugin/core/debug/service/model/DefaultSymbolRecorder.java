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
package ghidra.app.plugin.core.debug.service.model;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.Trace;
import ghidra.trace.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DefaultSymbolRecorder {

	private DefaultTraceRecorder recorder;
	private Trace trace;

	public DefaultSymbolRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
	}

	public CompletableFuture<Void> captureSymbols(TargetSymbolNamespace namespace,
			TaskMonitor monitor) {
		String path = PathUtils.toString(namespace.getPath());
		monitor.setMessage("Capturing symbols for " + path);
		return namespace.getSymbols().thenAccept(symbols -> {
			try (RecorderPermanentTransaction tid = RecorderPermanentTransaction.start(trace,
				"Capture types and symbols for " + path)) {
				TraceNamespaceSymbol ns = createNamespaceIfAbsent(path);
				monitor.setMessage("Capturing symbols for " + path);
				monitor.initialize(symbols.size());
				TraceEquateManager equateManager = trace.getEquateManager();
				for (TargetSymbol sym : symbols) {
					if (monitor.isCancelled()) {
						return;
					}
					monitor.incrementProgress(1);
					String symName = sym.getIndex();
					if (sym.isConstant()) {
						// TODO: Equate namespaces?
						TraceEquate equate = equateManager.getByName(symName);
						long symVal = sym.getValue().getOffset();
						if (equate != null && equate.getValue() == symVal) {
							continue;
						}
						try {
							equateManager.create(symName, symVal);
						}
						catch (DuplicateNameException | IllegalArgumentException e) {
							Msg.error(this, "Could not create equate: " + symName, e);
						}
						continue;
					}
					Address addr = recorder.getMemoryMapper().targetToTrace(sym.getValue());
					try {
						trace.getSymbolManager()
								.labels()
								.create(recorder.getSnap(), null, addr, symName, ns,
									SourceType.IMPORTED);
					}
					catch (InvalidInputException e) {
						Msg.error(this, "Could not add module symbol " + sym + ": " + e);
					}
					/**
					 * TODO: Lay down data type, if present
					 *
					 * TODO: Interpret "address" type correctly. A symbol with this type is itself
					 * the pointer. In other words, it is not specifying the type to lay down in
					 * memory.
					 */
				}
			}
		});
	}

	public CompletableFuture<Void> captureSymbols(TargetModule targetModule,
			TaskMonitor monitor) {
		CompletableFuture<? extends Map<String, ? extends TargetSymbolNamespace>> future =
			targetModule.fetchChildrenSupporting(TargetSymbolNamespace.class);
		// NOTE: I should expect exactly one namespace...
		return future.thenCompose(namespaces -> {
			AsyncFence fence = new AsyncFence();
			for (TargetSymbolNamespace ns : namespaces.values()) {
				fence.include(captureSymbols(ns, monitor));
			}
			return fence.ready();
		});
	}

	private TraceNamespaceSymbol createNamespaceIfAbsent(String path) {

		TraceSymbolManager symbolManager = trace.getSymbolManager();
		try {
			return symbolManager.namespaces()
					.add(path, symbolManager.getGlobalNamespace(), SourceType.IMPORTED);
		}
		catch (DuplicateNameException e) {
			Msg.info(this, "Namespace for module " + path +
				" already exists or another exists with a conflicting name. Using the existing one: " +
				e);
			TraceNamespaceSymbol ns = symbolManager.namespaces().getGlobalNamed(path);
			if (ns != null) {
				return ns;
			}
			Msg.error(this, "Existing namespace for " + path +
				" is not a plain namespace. Using global namespace.");
			return symbolManager.getGlobalNamespace();
		}
		catch (InvalidInputException | IllegalArgumentException e) {
			Msg.error(this,
				"Could not create namespace for new module: " + path + ". Using global namespace.",
				e);
			return symbolManager.getGlobalNamespace();
		}
	}
}
