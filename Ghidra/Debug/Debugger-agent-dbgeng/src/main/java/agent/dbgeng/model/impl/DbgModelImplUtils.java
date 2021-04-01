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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.model.AbstractDbgModel;

public enum DbgModelImplUtils {
	;
	public static CompletableFuture<Void> launch(AbstractDbgModel impl, DbgProcess process,
			List<String> args) {
		return process.fileExecAndSymbols(args.get(0));
	}

	public static <V> V noDupMerge(V first, V second) {
		throw new AssertionError();
	}
}
