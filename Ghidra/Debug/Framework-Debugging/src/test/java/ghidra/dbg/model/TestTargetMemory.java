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
package ghidra.dbg.model;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetMemory;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public class TestTargetMemory
		extends DefaultTestTargetObject<TestTargetMemoryRegion, TestTargetProcess>
		implements TargetMemory, TargetAccessConditioned {

	protected final SemisparseByteArray memory = new SemisparseByteArray();

	public TestTargetMemory(TestTargetProcess parent) {
		super(parent, "Memory", "Memory");
		changeAttributes(List.of(), Map.of(
			ACCESSIBLE_ATTRIBUTE_NAME, true //
		), "Initialized");
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		assertEquals(getModel().ram, address.getAddressSpace());
		byte[] data = new byte[length];
		memory.getData(address.getOffset(), data);
		CompletableFuture<byte[]> future = getModel().future(data);
		future.thenAccept(__ -> {
			listeners.fire.memoryUpdated(this, address, data);
		});
		return future;
	}

	public void setMemory(Address address, byte[] data) {
		assertEquals(getModel().ram, address.getAddressSpace());
		memory.putData(address.getOffset(), data);
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		setMemory(address, data);
		CompletableFuture<Void> future = getModel().future(null);
		future.thenAccept(__ -> {
			listeners.fire.memoryUpdated(this, address, data);
		});
		return future;
	}

	public TestTargetMemoryRegion addRegion(String name, AddressRange range, String flags) {
		TestTargetMemoryRegion region = new TestTargetMemoryRegion(this, name, range, flags);
		changeElements(List.of(), List.of(region), "Add test region: " + range);
		return region;
	}

	public boolean setAccessible(boolean accessible) {
		boolean old = isAccessible();
		changeAttributes(List.of(), Map.ofEntries(
			Map.entry(ACCESSIBLE_ATTRIBUTE_NAME, accessible)),
			"Set Test Memory Accessibility");
		return old;
	}
}
