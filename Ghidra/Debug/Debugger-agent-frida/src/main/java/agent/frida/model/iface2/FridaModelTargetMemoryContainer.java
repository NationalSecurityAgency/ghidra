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
package agent.frida.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaRegionInfo;
import agent.frida.manager.*;
import ghidra.dbg.target.TargetMemory;
import ghidra.program.model.address.Address;

public interface FridaModelTargetMemoryContainer extends FridaModelTargetObject, TargetMemory, //
		FridaEventsListenerAdapter {

	public FridaModelTargetMemoryRegion getTargetMemory(FridaMemoryRegionInfo region);

	public void regionAdded(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	public void regionReplaced(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	public void regionRemoved(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length);

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data);

}
