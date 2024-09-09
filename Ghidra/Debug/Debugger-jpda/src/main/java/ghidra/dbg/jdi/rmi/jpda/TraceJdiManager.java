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
package ghidra.dbg.jdi.rmi.jpda;

import java.util.HashMap;
import java.util.Map;

import com.sun.jdi.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

public class TraceJdiManager {

	private static final int STATIC_METHOD_SEPARATION = 3;
	public static final long BLOCK_SIZE = 0x1000L;
	public static final long DEFAULT_SECTION = 0x0000L;

	public static final String PREFIX_INVISIBLE = "_";
	public static final String DISPLAY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "display";
	public static final String STATE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "state";
	public static final String MODULE_NAME_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "module_name";
	public static final String ARCH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "arch";
	public static final String DEBUGGER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "debugger";
	public static final String OS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "os";
	public static final String ENDIAN_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "endian";
	public static final String ACCESSIBLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "accessible";

	private JdiManagerImpl manager;
	private TraceJdiArch arch;
	private TraceJdiHooks hooks;
	private TraceJdiMethods methods;
	private TraceJdiCommands commands;

	Map<String, Object> objectRegistry = new HashMap<>();
	Map<Object, String> reverseRegistry = new HashMap<>();
	RmiMethodRegistry remoteMethodRegistry = new RmiMethodRegistry();
	Map<Object, Boolean> scopeRegistry = new HashMap<>();

	protected final AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
	protected Long ramIndex = Long.valueOf(BLOCK_SIZE);
	protected final AddressSpace pool =
		new GenericAddressSpace("constantPool", 64, AddressSpace.TYPE_RAM, 0);
	protected Long poolIndex = Long.valueOf(0x0L);
	public AddressRangeImpl defaultRange;

	private Map<String, AddressRange> addressRangeByMethod = new HashMap<>();
	private Map<String, Method> methodsByKey = new HashMap<>();
	private Map<ReferenceType, AddressRange> addressRangeByClass = new HashMap<>();
	private Map<ReferenceType, AddressRange> cpAddressRangeByClass = new HashMap<>();

	private Map<String, DebugStatus> returnStatusMap = new HashMap<>();
	TargetObjectSchema rootSchema;

	public TraceJdiManager(JdiManagerImpl manager, Map<String, String> env) {
		this(manager);
		commands.ghidraTraceConnect(env.get("GHIDRA_TRACE_RMI_ADDR"));
		commands.ghidraTraceStart(env.get("OPT_TARGET_CLASS"));
	}

	// NB: Needed for testing
	public TraceJdiManager(JdiManagerImpl manager) {
		this.manager = manager;
		Address start = ram.getAddress(DEFAULT_SECTION);
		defaultRange = new AddressRangeImpl(start, start.add(BLOCK_SIZE - 1));
		rootSchema = RmiClient.loadSchema("jdi_schema.xml", "Debugger");

		arch = new TraceJdiArch();
		commands = new TraceJdiCommands(this); // Must precede methods/hooks
		methods = new TraceJdiMethods(this);
		hooks = new TraceJdiHooks(this);
		hooks.installHooks();
	}

	public JdiManagerImpl getJdi() {
		return manager;
	}

	public TraceJdiArch getArch() {
		return arch;
	}

	public TraceJdiCommands getCommands() {
		return commands;
	}

	public TraceJdiMethods getMethods() {
		return methods;
	}

	public TraceJdiHooks getHooks() {
		return hooks;
	}

	public RmiClient getClient() {
		return commands.state.client;
	}

	public void registerRemoteMethod(TraceJdiMethods methods, java.lang.reflect.Method m,
			String name) {
		String action = name;
		String display = name;
		String description = name;
		RmiMethodRegistry.TraceMethod annot = m.getAnnotation(RmiMethodRegistry.TraceMethod.class);
		if (annot == null) {
			return;
		}
		action = annot.action();
		if (annot.display() != null) {
			display = annot.display();
		}
		if (annot.description() != null) {
			description = annot.description();
		}
		int pcount = m.getParameterCount();
		if (pcount < 1) {
			return;
		}
		TargetObjectSchema schema = EnumerableTargetObjectSchema.ANY;
		RmiRemoteMethod method = new RmiRemoteMethod(rootSchema.getContext(), name, action, display,
			description, schema, methods, m);
		remoteMethodRegistry.putMethod(name, method);
	}

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

	public AddressRange putAddressRange(ReferenceType cls, AddressSet set) {
		if (set.isEmpty()) {
			addressRangeByClass.put(cls, defaultRange);
			return defaultRange;
		}
		AddressRange range = new AddressRangeImpl(set.getMinAddress(), set.getMaxAddress());
		addressRangeByClass.put(cls, range);
		return range;
	}

	public AddressRange getAddressRange(ReferenceType cls) {
		if (cls == null) {
			return defaultRange;
		}
		return addressRangeByClass.get(cls);
	}

	public ReferenceType getReferenceTypeForAddress(Address address) {
		for (ReferenceType ref : addressRangeByClass.keySet()) {
			AddressRange range = addressRangeByClass.get(ref);
			if (range.contains(address)) {
				return ref;
			}
		}
		return null;
	}

	public AddressRange getPoolAddressRange(ReferenceType cls, int sz) {
		if (cls == null) {
			return defaultRange;
		}
		AddressRange range = cpAddressRangeByClass.get(cls);
		if (range == null) {
			registerConstantPool(cls, sz);
			range = cpAddressRangeByClass.get(cls);
		}
		return range;
	}

	public void registerConstantPool(ReferenceType declaringType, int sz) {
		if (!cpAddressRangeByClass.containsKey(declaringType)) {
			if (manager.getCurrentVM().canGetConstantPool()) {
				long length = sz == 0 ? 2 : sz;
				synchronized (cpAddressRangeByClass) {
					Address start = pool.getAddress(poolIndex);
					AddressRangeImpl range =
						new AddressRangeImpl(start, start.add(length - 1));
					if (!cpAddressRangeByClass.containsKey(declaringType)) {
						cpAddressRangeByClass.put(declaringType, range);
						poolIndex += length; //bytecodes.length;
					}
				}
			}
		}
	}

	public ReferenceType getReferenceTypeForPoolAddress(Address address) {
		for (ReferenceType ref : cpAddressRangeByClass.keySet()) {
			AddressRange range = cpAddressRangeByClass.get(ref);
			if (range.contains(address)) {
				return ref;
			}
		}
		return null;
	}

	public AddressRange getAddressRange(Method method) {
		if (method == null) {
			return defaultRange;
		}
		AddressRange range = addressRangeByMethod.get(methodToKey(method));
		if (range == null) {
			return defaultRange;
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

	public Address getAddressFromLocation(Location location) {
		AddressRange addressRange = getAddressRange(location.method());
		if (addressRange == null) {
			return getAddressSpace("ram").getAddress(-1L);
		}
		long codeIndex = location.codeIndex();
		return addressRange.getMinAddress().add(codeIndex < 0 ? 0 : codeIndex);

	}

	public Location getLocation(Address address) {
		Method method = getMethodForAddress(address);
		long codeIndex = address.subtract(getAddressRange(method).getMinAddress());
		return method.locationOfCodeIndex(codeIndex);
	}

	public static String methodToKey(Method method) {
		return method.toString();
	}

	public AddressRange registerAddressesForMethod(Method method) {
		byte[] bytecodes = method.bytecodes();
		if (bytecodes == null) {
			return null;
		}
		int length = bytecodes.length;
		if (length <= 0) {
			return null;
		}
		synchronized (addressRangeByMethod) {
			Address start = ram.getAddress(ramIndex);
			AddressRangeImpl range =
				new AddressRangeImpl(start, start.add(length - 1));
			String key = methodToKey(method);
			//System.err.println(Long.toHexString(ramIndex)+":"+key+":"+bytecodes.length+" "+Long.toHexString(bytecodes[0]));
			if (!methodsByKey.containsKey(key)) {
				methodsByKey.put(key, method);
			}
			if (!addressRangeByMethod.containsKey(key)) {
				addressRangeByMethod.put(key, range);
				ramIndex = range.getMaxAddress().getUnsignedOffset() + STATIC_METHOD_SEPARATION;
				return range;
			}
			return addressRangeByMethod.get(key);
		}
	}

	public String recordPath(Object obj, String path, String key) {
		if (path.endsWith("]")) {
			path += "." + key;
		}
		else {
			path += key(key);
		}
		objectRegistry.put(path, obj);
		if (!reverseRegistry.containsKey(obj)) {
			reverseRegistry.put(obj, path);
		}
		return path;
	}

	public Object objForPath(String path) {
		return objectRegistry.get(path);
	}

	public String pathForObj(Object obj) {
		if (!reverseRegistry.containsKey(obj)) {
			if (objectRegistry.containsValue(obj)) {
				Msg.error(this, "MISSING path for " + obj);
			}
			return null;
		}
		return reverseRegistry.get(obj);
	}

	public boolean getScope(Object ctxt) {
		Boolean scope = scopeRegistry.get(ctxt);
		if (scope == null) {
			scope = true;
		}
		return scope;
	}

	public void toggleScope(Object ctxt) {
		Boolean scope = scopeRegistry.get(ctxt);
		if (scope == null) {
			scope = true;
		}
		scopeRegistry.put(ctxt, !scope);
	}

	private String sanitize(String name) {
		if (name == null) {
			return name;
		}
		name = name.replace("[", "");
		name = name.replace("]", "");
		return name;
	}

	public String key(String key) {
		return "[" + sanitize(key) + "]";
	}

	public DebugStatus getReturnStatus(String eventName) {
		return returnStatusMap.get(eventName);
	}

	public void setReturnStatus(String eventName, String statusString) {
		DebugStatus status = DebugStatus.BREAK;
		try {
			status = DebugStatus.valueOf(statusString.toUpperCase());
		}
		catch (IllegalArgumentException e) {
			// IGNORE
		}
		returnStatusMap.put(eventName, status);
	}

	public void bumpRamIndex() {
		synchronized (addressRangeByMethod) {
			if (ramIndex % BLOCK_SIZE != 0) {
				ramIndex = (ramIndex / BLOCK_SIZE + 1) * BLOCK_SIZE;
			}
		}
	}

}
