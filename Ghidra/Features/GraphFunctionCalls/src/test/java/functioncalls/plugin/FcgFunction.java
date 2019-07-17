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
package functioncalls.plugin;

import java.util.*;

import ghidra.program.model.FunctionTestDouble;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

/**
 * A fake function double for use in testing the {@link FunctionCallGraphPlugin}
 */
public class FcgFunction extends FunctionTestDouble {

	private Set<Function> calledFunctions = new HashSet<>();
	private Set<Function> callingFunctions = new HashSet<>();
	private Address entry;

	public FcgFunction(String name, Address entry) {
		super(name);
		this.entry = entry;
	}

	public void addCalledFunction(Function f) {
		calledFunctions.add(f);
	}

	public void addCallerFunction(Function f) {
		callingFunctions.add(f);
	}

	@Override
	public Address getEntryPoint() {
		return entry;
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		return Collections.unmodifiableSet(calledFunctions);
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		return Collections.unmodifiableSet(callingFunctions);
	}

	@Override
	public String toString() {
		return super.toString() + " @ " + getEntryPoint().getOffset();
	}
}
