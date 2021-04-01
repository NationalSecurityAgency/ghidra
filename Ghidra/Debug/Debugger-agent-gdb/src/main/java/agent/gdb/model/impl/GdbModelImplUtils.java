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
package agent.gdb.model.impl;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbThread;
import ghidra.dbg.util.ShellUtils;

public enum GdbModelImplUtils {
	;
	public static CompletableFuture<GdbThread> launch(GdbModelImpl impl, GdbInferior inferior,
			List<String> args) {
		// Queue all these up to avoid other commands getting between.
		CompletableFuture<Void> feas = inferior.fileExecAndSymbols(args.get(0));
		CompletableFuture<Void> sargs =
			inferior.setVar("args", ShellUtils.generateLine(args.subList(1, args.size())));
		CompletableFuture<Void> both = CompletableFuture.allOf(feas, sargs);
		if (impl.noStarti) {
			return both.thenCombine(inferior.start(), (__, t) -> t);
		}
		else {
			return both.thenCombine(inferior.starti(), (__, t) -> t).exceptionally(ex -> {
				impl.noStarti = true;
				// TODO: Check that the error is actually Undefined command: "starti"
				return null;
			}).thenCompose(thread -> {
				if (thread == null) {
					return inferior.start();
				}
				return CompletableFuture.completedStage(thread);
			});
		}
	}

	public static <V> V noDupMerge(V first, V second) {
		throw new AssertionError();
	}
}
