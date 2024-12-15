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
package ghidra.app.plugin.core.debug.service.model.interfaces;

import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import ghidra.dbg.target.*;
import ghidra.debug.api.model.DebuggerMemoryMapper;
import ghidra.program.model.address.*;

@Deprecated(forRemoval = true, since = "11.3")
public interface AbstractRecorderMemory {

	public void addMemory(TargetMemory memory);

	public void addRegion(TargetMemoryRegion region, TargetMemory memory);

	public void removeMemory(TargetMemory invalid);

	public boolean removeRegion(TargetObject invalid);

	public CompletableFuture<byte[]> readMemory(Address address, int length);

	public CompletableFuture<Void> writeMemory(Address address, byte[] data);

	/**
	 * Get accessible memory, as viewed in the trace
	 * 
	 * @param pred an additional predicate applied via "AND" with accessibility
	 * @param memMapper target-to-trace mapping utility
	 * @return the computed set
	 */
	public AddressSet getAccessibleMemory(Predicate<TargetMemory> pred,
			DebuggerMemoryMapper memMapper);

	public AddressRange alignAndLimitToFloor(Address targetAddress, int length);
}
