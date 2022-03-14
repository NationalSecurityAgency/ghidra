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
//Decompile the function at the cursor, then build data-flow graph (AST) with flow edges
//@category PCode

import ghidra.app.plugin.core.decompile.actions.PCodeCombinedGraphTask;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphTask;
import ghidra.app.services.GraphDisplayBroker;

public class GraphASTAndFlowScript extends GraphASTScript {

	protected PCodeDfgGraphTask createTask(GraphDisplayBroker graphDisplayBroker) {
		return new PCodeCombinedGraphTask(state.getTool(), graphDisplayBroker, high);
	}
}
