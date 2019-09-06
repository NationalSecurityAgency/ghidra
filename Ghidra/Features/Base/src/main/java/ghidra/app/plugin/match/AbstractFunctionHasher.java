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
package ghidra.app.plugin.match;

import generic.stl.Pair;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;

public abstract class AbstractFunctionHasher implements FunctionHasher {

	@Override
	public final long hash(Function function, TaskMonitor monitor) throws CancelledException {
		Program program = function.getProgram();
		Pair<Integer, ArrayList<CodeUnit>> pair =
			getAllCodeUnits(monitor, program, new AddressSet(function.getBody()));
		try {
			return hash(monitor, pair.second, pair.first);
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}

	protected final Pair<Integer, ArrayList<CodeUnit>> getAllCodeUnits(TaskMonitor monitor,
			Program prog, AddressSetView set) {
		int totalLength = 0;
		ArrayList<CodeUnit> arr = new ArrayList<CodeUnit>();
		CodeUnitIterator iter = prog.getListing().getCodeUnits(set, true);
		while (!monitor.isCancelled() && iter.hasNext()) {
			CodeUnit next = iter.next();
			arr.add(next);
			totalLength += next.getLength();
		}
		return new Pair<Integer, ArrayList<CodeUnit>>(totalLength, arr);

	}

	protected abstract long hash(TaskMonitor monitor, ArrayList<CodeUnit> units, int byteCount)
			throws MemoryAccessException, CancelledException;
}
