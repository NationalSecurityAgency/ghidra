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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.TargetDataTypeConverter;
import ghidra.program.model.data.*;
import ghidra.trace.model.Trace;
import ghidra.util.task.TaskMonitor;

public class DefaultDataTypeRecorder {

	//private DefaultTraceRecorder recorder;
	private Trace trace;
	private final TargetDataTypeConverter typeConverter;

	public DefaultDataTypeRecorder(DefaultTraceRecorder recorder) {
		//this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.typeConverter = new TargetDataTypeConverter(trace.getDataTypeManager());
	}

	public CompletableFuture<Void> captureDataTypes(TargetDataTypeNamespace namespace,
			TaskMonitor monitor) {
		String path = PathUtils.toString(namespace.getPath());
		monitor.setMessage("Capturing data types for " + path);
		return namespace.getTypes().thenCompose(types -> {
			monitor.initialize(types.size());
			AsyncFence fence = new AsyncFence();
			List<DataType> converted = new ArrayList<>();
			for (TargetNamedDataType type : types) {
				if (monitor.isCancelled()) {
					fence.ready().cancel(false);
					return AsyncUtils.nil();
				}
				monitor.incrementProgress(1);
				fence.include(typeConverter.convertTargetDataType(type).thenAccept(converted::add));
			}
			return fence.ready().thenApply(__ -> converted);
		}).thenAccept(converted -> {
			if (converted == null) {
				return;
			}
			try (RecorderPermanentTransaction tid =
				RecorderPermanentTransaction.start(trace, "Capture data types for " + path)) {
				// NOTE: createCategory is actually getOrCreate
				Category category =
					trace.getDataTypeManager().createCategory(new CategoryPath("/" + path));
				for (DataType dataType : converted) {
					category.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
			}
		});
	}

	public CompletableFuture<Void> captureDataTypes(TargetModule targetModule,
			TaskMonitor monitor) {
		CompletableFuture<? extends Map<String, ? extends TargetDataTypeNamespace>> future =
			targetModule.fetchChildrenSupporting(TargetDataTypeNamespace.class);
		// NOTE: I should expect exactly one namespace...
		return future.thenCompose(namespaces -> {
			AsyncFence fence = new AsyncFence();
			for (TargetDataTypeNamespace ns : namespaces.values()) {
				fence.include(captureDataTypes(ns, monitor));
			}
			return fence.ready();
		});
	}
}
