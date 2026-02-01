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
package ghidra.features.bsim.query;

import ghidra.app.decompiler.DecompileException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for a task that is initialized with a program, and a number of workers.
 * Then the task is replicated for that number of workers, and each replicated task
 * has its -decompile- method called some number of times with different functions
 * and produces some output object
 */
public interface DecompileFunctionTask {
	public void initializeGlobal(Program program);

	public DecompileFunctionTask clone(int worker) throws DecompileException;

	public void decompile(Function func, TaskMonitor monitor);

	public void shutdown();
}
