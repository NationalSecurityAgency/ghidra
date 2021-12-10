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
import java.util.function.Supplier;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbThread;
import ghidra.dbg.util.ShellUtils;

public enum GdbModelImplUtils {
	;

	/**
	 * Perform the file-args-start sequence to launch a target in an inferior
	 * 
	 * @param inferior the inferior to assign the target
	 * @param args the command-line arguments, including the executable at args[0]
	 * @param useStarti true to use {@code starti}, false to use {@code start}
	 * @param postFile a caller-specified routine to execute after the {@code file} part of the
	 *            sequence. This is useful to grab auto-derived environment information
	 * @return a future which completes with the initial thread of the target
	 */
	public static CompletableFuture<GdbThread> launch(GdbInferior inferior,
			List<String> args, boolean useStarti, Supplier<CompletableFuture<Void>> postFile) {
		// Queue all these up to avoid other commands getting between.
		CompletableFuture<Void> feas = inferior.fileExecAndSymbols(args.get(0));
		CompletableFuture<Void> post = postFile.get();
		CompletableFuture<Void> sargs =
			inferior.setVar("args", ShellUtils.generateLine(args.subList(1, args.size())));
		CompletableFuture<GdbThread> start = useStarti ? inferior.starti() : inferior.start();
		return feas
				.thenCombine(post, (v, t) -> t)
				.thenCombine(sargs, (v, t) -> t)
				.thenCombine(start, (v, t) -> t);
	}

	public static <V> V noDupMerge(V first, V second) {
		throw new AssertionError();
	}
}
