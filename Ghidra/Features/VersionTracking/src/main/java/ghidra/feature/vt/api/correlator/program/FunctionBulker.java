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
package ghidra.feature.vt.api.correlator.program;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for computing a list of hashes that characterize a function's structure.
 * Used for bulk similarity comparison between function pairs.
 */
public interface FunctionBulker {
	/**
	 * Compute a list of hashes representing the structure of the given function.
	 *
	 * @param function the function to hash
	 * @param monitor task monitor for cancellation
	 * @return list of hashes characterizing the function
	 * @throws CancelledException if the operation is cancelled
	 */
	public List<Long> hashes(Function function, TaskMonitor monitor) throws CancelledException;
}
