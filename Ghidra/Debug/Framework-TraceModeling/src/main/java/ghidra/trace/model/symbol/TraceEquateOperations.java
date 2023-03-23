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
package ghidra.trace.model.symbol;

import java.util.Collection;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface TraceEquateOperations {
	AddressSetView getReferringAddresses(Lifespan span);

	void clearReferences(Lifespan span, AddressSetView asv, TaskMonitor monitor)
			throws CancelledException;

	void clearReferences(Lifespan span, AddressRange range, TaskMonitor monitor)
			throws CancelledException;

	TraceEquate getReferencedByValue(long snap, Address address, int operandIndex, long value);

	Collection<? extends TraceEquate> getReferenced(long snap, Address address, int operandIndex);

	Collection<? extends TraceEquate> getReferenced(long snap, Address address);
}
