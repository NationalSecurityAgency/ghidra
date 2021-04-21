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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.*;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.jdi.manager.JdiManager;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.*;

public class JdiModelImpl extends AbstractDebuggerObjectModel {

	protected JdiModelTargetRoot root;
	protected final CompletableFuture<JdiModelTargetRoot> completedRoot;

	public static final long BLOCK_SIZE = 0x1000L;
	public static final long DEFAULT_SECTION = 0x0000L;

	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(JdiModelTargetRoot.class);

	protected JdiManager jdi;
	protected final AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
	protected Long ramIndex = Long.valueOf(0x1000L);
	protected final AddressSpace pool =
		new GenericAddressSpace("constantPool", 64, AddressSpace.TYPE_RAM, 0);
	protected Long poolIndex = Long.valueOf(0x0L);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { ram, pool });
	public AddressRangeImpl defaultRange;

	private Map<String, AddressRange> addressRangeByMethod = new HashMap<>();
	private Map<String, Method> methodsByKey = new HashMap<>();
	private Map<JdiModelTargetReferenceType, AddressRange> addressRangeByClass = new HashMap<>();

	public JdiModelImpl() {
		this.jdi = JdiManager.newInstance();
		//System.out.println(XmlSchemaContext.serialize(SCHEMA_CTX));
		this.root = new JdiModelTargetRoot(this, ROOT_SCHEMA);
		//this.root = new JdiModelTargetRoot(this, EnumerableTargetObjectSchema.OBJECT);
		this.completedRoot = CompletableFuture.completedFuture(root);

		Address start = ram.getAddress(0L);
		this.defaultRange = new AddressRangeImpl(start, start.add(BLOCK_SIZE));
		addModelRoot(root);
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return completedRoot;
	}

	@Override
	public String getBrief() {
		return "JDI@" + Integer.toHexString(System.identityHashCode(this));
	}

	@Override
	public AddressSpace getAddressSpace(String name) {
		switch (name) {
			case "ram":
				return ram;
			case "constantPool":
				return pool;
			default:
				return null;
		}
	}

	@Override
	public CompletableFuture<Void> close() {
		jdi.terminate();
		return super.close();
	}

	public JdiModelTargetRoot getRoot() {
		return root;
	}

	public JdiManager getManager() {
		return jdi;
	}

	public static String methodToKey(Method method) {
		return method.toString();
	}

	public void registerMethod(Method method) {
		if (method == null) {
			return;
		}
		if (!methodsByKey.containsValue(method)) {
			methodsByKey.put(methodToKey(method), method);
		}
		if (!addressRangeByMethod.containsKey(methodToKey(method))) {
			ReferenceType declaringType = method.declaringType();
			if (declaringType instanceof ClassType) {
				JdiModelTargetVM targetVM = getTargetVM(declaringType);
				JdiModelTargetReferenceType classRef =
					(JdiModelTargetReferenceType) targetVM.getTargetObject(declaringType);
				if (classRef != null) {
					JdiModelTargetSectionContainer sectionContainer = classRef.sections;
					for (Method m : declaringType.methods()) {
						if (m.location() != null && targetVM.vm.canGetBytecodes()) {
							byte[] bytecodes = m.bytecodes();
							int length = bytecodes.length;
							if (length > 0) {
								synchronized (ramIndex) {
									Address start = ram.getAddress(ramIndex);
									AddressRangeImpl range =
										new AddressRangeImpl(start, start.add(BLOCK_SIZE - 1));
									String key = methodToKey(m);
									if (addressRangeByMethod.containsKey(key)) {
										System.err.println("non-null location: " + m.location() +
											" with " + length + " bytes");
										//throw new RuntimeException("non-null location: " +
										//	m.location() + " with " + length + " bytes");
									}
									addressRangeByMethod.put(key, range);
									if (sectionContainer != null) {
										sectionContainer.addSection(m);
									}
									else {
										System.err.println("null sectionContainer");
									}
									ramIndex += 0x1000; //bytecodes.length;
								}
							}
							else {
								Address start = ram.getAddress(DEFAULT_SECTION);
								AddressRangeImpl range =
									new AddressRangeImpl(start, start.add(BLOCK_SIZE - 1));
								String key = methodToKey(m);
								if (addressRangeByMethod.containsKey(key)) {
									throw new RuntimeException("non-null location: " +
										m.location() + " with " + length + " bytes");
								}
								addressRangeByMethod.put(key, range);
							}
						}
					}
				}
			}
		}
	}

	public void registerConstantPool(JdiModelTargetReferenceType classType, int size) {
		if (!addressRangeByClass.containsKey(classType)) {
			ReferenceType declaringType = classType.reftype;
			if (declaringType instanceof ClassType) {
				JdiModelTargetVM targetVM = getTargetVM(declaringType);
				if (targetVM.vm.canGetConstantPool()) {
					long length = size;
					if (length > 0) {
						synchronized (poolIndex) {
							Address start = pool.getAddress(poolIndex);
							length = (length % BLOCK_SIZE + 1) * BLOCK_SIZE;
							AddressRangeImpl range =
								new AddressRangeImpl(start, start.add(length - 1));
							if (addressRangeByClass.containsKey(classType)) {
								System.err.println("non-null location: " + classType + " with " +
									length + " bytes");
							}
							addressRangeByClass.put(classType, range);
							poolIndex += length; //bytecodes.length;
						}
					}
				}
			}
		}
	}

	public JdiModelTargetVM getTargetVM(Mirror mirror) {
		return root.vms.getTargetVM(mirror.virtualMachine());
	}

	public AddressRange getAddressRange(Method method) {
		if (method == null) {
			return defaultRange;
		}
		AddressRange range = addressRangeByMethod.get(methodToKey(method));
		if (range == null) {
			registerMethod(method);
			range = addressRangeByMethod.get(methodToKey(method));
		}
		return range;
	}

	public Method getMethodForAddress(Address address) {
		for (String methodName : addressRangeByMethod.keySet()) {
			AddressRange range = addressRangeByMethod.get(methodName);
			if (range.contains(address)) {
				return methodsByKey.get(methodName);
			}
		}
		return null;
	}

	public Location getLocation(Address address) {
		Method method = getMethodForAddress(address);
		long codeIndex = address.subtract(getAddressRange(method).getMinAddress());
		return method.locationOfCodeIndex(codeIndex);
	}

	public AddressRange getAddressRange(JdiModelTargetReferenceType classType, int sz) {
		AddressRange range = addressRangeByClass.get(classType);
		if (range == null) {
			registerConstantPool(classType, sz);
			range = addressRangeByClass.get(classType);
		}
		return range;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

}
