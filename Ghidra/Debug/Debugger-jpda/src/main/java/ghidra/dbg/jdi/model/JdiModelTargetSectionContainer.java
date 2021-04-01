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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.Method;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

@TargetObjectSchemaInfo(
	name = "TargetSectionContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetSection.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetSectionContainer extends JdiModelTargetObjectImpl
		implements TargetMemory {

	protected final JdiModelTargetReferenceType reftype;

	private final Map<String, JdiModelTargetSection> sectionsByName = new HashMap<>();
	private JdiModelTargetConstantPool constantPool;

	//private JdiModelTargetConstantPool constantPool;

	public JdiModelTargetSectionContainer(JdiModelTargetReferenceType reftype) {
		super(reftype, "Sections");
		this.reftype = reftype;
		new JdiModelTargetSection(this); // default section
	}

	protected void updateUsingSections(List<Method> methods) {
		setElements(sectionsByName.values(), Map.of(), "Refreshed");
	}

	@Override
	protected CompletableFuture<Void> requestAttributes(boolean refresh) {

		constantPool = new JdiModelTargetConstantPool(this, reftype.reftype.constantPool(), false);
		changeAttributes(List.of(), List.of( //
			constantPool //
		), Map.of(), "Initialized");

		return CompletableFuture.completedFuture(null);
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		updateUsingSections(reftype.reftype.methods());
		return CompletableFuture.completedFuture(null);
	}

	protected synchronized JdiModelTargetSection getTargetSection(Method method) {
		return sectionsByName.computeIfAbsent(JdiModelImpl.methodToKey(method),
			n -> new JdiModelTargetSection(this, method, true));
	}

	public synchronized JdiModelTargetSection getTargetSectionIfPresent(String name) {
		return sectionsByName.get(name);
	}

	@Override
	public CompletableFuture<Void> init() {
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetSection method : sectionsByName.values()) {
			fence.include(method.init());
		}
		return fence.ready();
	}

	public JdiModelTargetReferenceType getClassType() {
		return reftype;
	}

	public void addSection(Method method) {
		if (impl.getAddressRange(method) != null) {
			JdiModelTargetSection targetSection = getTargetSection(method);
			sectionsByName.put(JdiModelImpl.methodToKey(method), targetSection);
			changeElements(List.of(), List.of(targetSection), Map.of(), "Refreshed");
		}
		else {
			System.err.println("addSection returned null: " + method.location());
		}
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		AddressSpace addressSpace = address.getAddressSpace();
		if (addressSpace.equals(impl.getAddressSpace("ram"))) {
			byte[] bytes = new byte[length];
			Method method = impl.getMethodForAddress(address);
			if (method != null && targetVM.vm.canGetBytecodes()) {
				byte[] bytecodes = method.bytecodes();
				int i = 0;
				for (byte b : bytecodes) {
					bytes[i++] = b;
					if (i >= length)
						break;
				}
			}
			else {
				for (int i = 0; i < length; i++) {
					bytes[i] = (byte) 0xFF;
				}
			}
			listeners.fire.memoryUpdated(this, address, bytes);
			return CompletableFuture.completedFuture(bytes);
		}
		if (addressSpace.equals(impl.getAddressSpace("constantPool"))) {
			byte[] bytes = constantPool.getPool();
			listeners.fire.memoryUpdated(this, address, bytes);
			return CompletableFuture.completedFuture(bytes);
		}
		throw new RuntimeException();
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return CompletableFuture.completedFuture(null);
	}

}
