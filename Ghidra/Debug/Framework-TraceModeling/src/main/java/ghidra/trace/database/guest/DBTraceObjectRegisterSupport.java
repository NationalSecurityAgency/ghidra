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
package ghidra.trace.database.guest;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Stream;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPredicates.Align;
import ghidra.dbg.util.PathUtils;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.guest.*;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.target.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.Msg;

public enum DBTraceObjectRegisterSupport {
	// TODO: Could/should this be done by an analyzer, instead of being internal trace logic?
	INSTANCE;

	private static final TraceDomainObjectListener HANDLER = new TraceDomainObjectListener() {
		{
			listenFor(TraceObjectChangeType.VALUE_CREATED, INSTANCE::objectValueCreated);
			listenFor(TraceSymbolChangeType.ADDED, INSTANCE::symbolAdded);
			listenFor(TraceOverlaySpaceChangeType.ADDED, INSTANCE::spaceAdded);
			listenFor(TracePlatformChangeType.MAPPING_ADDED, INSTANCE::guestMappingAdded);
		}
	};

	static class RegisterValueException extends Exception {
		public RegisterValueException(String message) {
			super(message);
		}
	}

	static class LazyValues {
		private final TraceObjectValue registerValue;
		private BigInteger value;
		private int bitLength = -1;
		private byte[] be;
		private byte[] le;

		public LazyValues(TraceObjectValue registerValue) {
			this.registerValue = registerValue;
		}

		BigInteger convertRegisterValueToBigInteger() throws RegisterValueException {
			Object val = registerValue.getValue();
			if (val instanceof String s) {
				try {
					return new BigInteger(s, 16);
				}
				catch (NumberFormatException e) {
					throw new RegisterValueException(
						"Invalid register value " + s + ". Must be hex digits only.");
				}
			}
			else if (val instanceof byte[] arr) {
				// NOTE: Reg object values are always big endian
				return new BigInteger(1, arr);
			}
			else if (val instanceof Byte b) {
				return BigInteger.valueOf(b);
			}
			else if (val instanceof Short s) {
				return BigInteger.valueOf(s);
			}
			else if (val instanceof Integer i) {
				return BigInteger.valueOf(i);
			}
			else if (val instanceof Long l) {
				return BigInteger.valueOf(l);
			}
			else if (val instanceof Address a) {
				return a.getOffsetAsBigInteger();
			}
			throw new RegisterValueException(
				"Cannot convert register value: (" + registerValue.getValue().getClass() + ") '" +
					registerValue.getValue() +
					"'");
		}

		int getRegisterValueBitLength() throws RegisterValueException {
			Object objBitLength = registerValue.getParent()
					.getValue(registerValue.getMinSnap(), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME)
					.getValue();
			if (!(objBitLength instanceof Number)) {
				throw new RegisterValueException(
					"Register length is not numeric: (" + objBitLength.getClass() + ") '" +
						objBitLength + "'");
			}
			return ((Number) objBitLength).intValue();
		}

		BigInteger getValue() throws RegisterValueException {
			if (value != null) {
				return value;
			}
			return value = convertRegisterValueToBigInteger();
		}

		int getBitLength() throws RegisterValueException {
			if (bitLength != -1) {
				return bitLength;
			}
			return bitLength = getRegisterValueBitLength();
		}

		int getByteLength() throws RegisterValueException {
			return (getBitLength() + 7) / 8;
		}

		byte[] getBytesBigEndian() throws RegisterValueException {
			if (be != null) {
				return be;
			}
			return be = Utils.bigIntegerToBytes(getValue(), getByteLength(), true);
		}

		byte[] getBytesLittleEndian() throws RegisterValueException {
			if (le != null) {
				return le;
			}
			return le = Utils.bigIntegerToBytes(getValue(), getByteLength(), false);
		}

		public byte[] getBytes(boolean isBigEndian) throws RegisterValueException {
			return isBigEndian ? getBytesBigEndian() : getBytesLittleEndian();
		}
	}

	protected AddressSpace findRegisterOverlay(TraceObject object) {
		TraceObject container = object
				.queryCanonicalAncestorsTargetInterface(TargetRegisterContainer.class)
				.findFirst()
				.orElse(null);
		if (container == null) {
			return null;
		}
		String pathStr = container.getCanonicalPath().toString();
		Trace trace = object.getTrace();
		return trace.getMemoryManager()
				.getOrCreateOverlayAddressSpace(pathStr,
					trace.getBaseAddressFactory().getRegisterSpace());
	}

	protected AddressSpace findRegisterOverlay(TraceObjectValue objectValue) {
		return findRegisterOverlay(objectValue.getParent());
	}

	protected void onValueCreatedTransferToPlatformRegister(TraceObjectValue registerValue,
			TracePlatform platform, String name, LazyValues lazy) throws RegisterValueException {
		Register register = platform.getLanguage().getRegister(name);
		if (register == null) {
			return;
		}

		Address hostAddr = platform.mapGuestToHost(register.getAddress());
		if (hostAddr == null) {
			return;
		}
		AddressSpace hostSpace = hostAddr.getAddressSpace();
		TraceMemoryManager mem = registerValue.getTrace().getMemoryManager();
		long minSnap = registerValue.getMinSnap();
		if (hostSpace.isMemorySpace()) {
			mem.getMemorySpace(hostSpace, true)
					.setValue(platform, minSnap, new RegisterValue(register, lazy.getValue()));
		}
		else if (hostSpace.isRegisterSpace()) {
			AddressSpace overlay = findRegisterOverlay(registerValue);
			if (overlay == null) {
				return;
			}
			mem.getMemorySpace(overlay, true)
					.setValue(platform, minSnap, new RegisterValue(register, lazy.getValue()));
		}
		else {
			throw new AssertionError();
		}
	}

	protected void transferValueToPlatformRegister(TraceObjectValue registerValue,
			TracePlatform platform, TraceMemorySpace mem, Register register) {
		LazyValues lazy = new LazyValues(registerValue);
		try {
			mem.setValue(platform, registerValue.getMinSnap(),
				new RegisterValue(register, lazy.getValue()));
		}
		catch (RegisterValueException e) {
			Msg.error(this, e.getMessage());
		}
	}

	protected String getRegisterName(TraceObject registerObject) {
		String name = registerObject.getCanonicalPath().key();
		if (PathUtils.isIndex(name)) {
			return PathUtils.parseIndex(name);
		}
		return name;
	}

	protected void onSpaceAddedCheckTransferObjectToPlatformRegister(TraceObject registerObject,
			TracePlatform platform, TraceMemorySpace mem) {
		String name = getRegisterName(registerObject);
		Register register = platform.getLanguage().getRegister(name);
		if (register == null || !register.getAddressSpace().isRegisterSpace()) {
			return;
		}
		for (TraceObjectValue registerValue : it(registerObject.getOrderedValues(Lifespan.ALL,
			TargetRegister.VALUE_ATTRIBUTE_NAME, true))) {
			transferValueToPlatformRegister(registerValue, platform, mem, register);
		}
	}

	protected void onSpaceAddedCheckTransferToPlatformRegisters(TracePlatform platform,
			TraceObject regContainer, TraceMemorySpace mem) {
		for (TraceObjectValPath path : it(
			regContainer.querySuccessorsTargetInterface(Lifespan.ALL, TargetRegister.class))) {
			TraceObject registerObject =
				path.getDestination(platform.getTrace().getObjectManager().getRootObject());
			onSpaceAddedCheckTransferObjectToPlatformRegister(registerObject, platform, mem);
		}
	}

	protected TraceMemorySpace getMemorySpace(TraceObject object, TraceLabelSymbol label) {
		Address hostAddr = label.getAddress();
		AddressSpace hostSpace = hostAddr.getAddressSpace();
		TraceMemoryManager mem = label.getTrace().getMemoryManager();
		if (hostSpace.isMemorySpace()) {
			return mem.getMemorySpace(hostSpace, true);
		}
		else if (hostSpace.isRegisterSpace()) {
			AddressSpace overlay = findRegisterOverlay(object);
			return mem.getMemorySpace(overlay, true);
		}
		else {
			throw new AssertionError();
		}
	}

	protected void transferRegisterValueToLabel(TraceObjectValue registerValue,
			TraceLabelSymbol label, byte[] value) {
		TraceMemorySpace mem = getMemorySpace(registerValue.getParent(), label);
		Address hostAddr = label.getAddress();
		long minSnap = registerValue.getMinSnap();
		Address address = mem.getAddressSpace().getOverlayAddress(hostAddr);
		mem.putBytes(minSnap, address, ByteBuffer.wrap(value));
	}

	protected static <T> Iterable<T> it(Stream<T> stream) {
		return () -> stream.iterator();
	}

	protected void transferRegisterObjectToLabel(TraceObject registerObject, TraceLabelSymbol label,
			boolean isBigEndian) {
		TraceMemorySpace mem = getMemorySpace(registerObject, label);
		Address address = mem.getAddressSpace().getOverlayAddress(label.getAddress());
		for (TraceObjectValue registerValue : it(registerObject.getOrderedValues(
			label.getLifespan(), TargetRegister.VALUE_ATTRIBUTE_NAME, true))) {
			LazyValues lazy = new LazyValues(registerValue);
			try {
				long minSnap = registerValue.getMinSnap();
				mem.putBytes(minSnap, address, ByteBuffer.wrap(lazy.getBytes(isBigEndian)));
			}
			catch (RegisterValueException e) {
				Msg.error(this, e.getMessage());
			}
		}
	}

	public void onValueCreatedTransfer(TraceObjectValue registerValue)
			throws RegisterValueException {
		TraceObject registerObject = registerValue.getParent();
		Trace trace = registerValue.getTrace();
		LazyValues lazy = new LazyValues(registerValue);

		String name = getRegisterName(registerObject);

		TracePlatformManager platformManager = trace.getPlatformManager();
		onValueCreatedTransferToPlatformRegister(registerValue, platformManager.getHostPlatform(),
			name, lazy);
		for (TracePlatform platform : platformManager.getGuestPlatforms()) {
			onValueCreatedTransferToPlatformRegister(registerValue, platform, name, lazy);
		}

		TraceNamespaceSymbolView namespaces = trace.getSymbolManager().namespaces();
		TraceNamespaceSymbol nsRegMapBE =
			namespaces.getGlobalNamed(InternalTracePlatform.REG_MAP_BE);
		if (nsRegMapBE != null) {
			for (TraceLabelSymbol label : trace.getSymbolManager()
					.labels()
					.getChildrenNamed(name, nsRegMapBE)) {
				transferRegisterValueToLabel(registerValue, label, lazy.getBytesBigEndian());
			}
		}
		TraceNamespaceSymbol nsRegMapLE =
			namespaces.getGlobalNamed(InternalTracePlatform.REG_MAP_LE);
		if (nsRegMapLE != null) {
			for (TraceLabelSymbol label : trace.getSymbolManager()
					.labels()
					.getChildrenNamed(name, nsRegMapLE)) {
				transferRegisterValueToLabel(registerValue, label, lazy.getBytesLittleEndian());
			}
		}
	}

	protected boolean isRegisterValue(TraceObjectValue objectValue) {
		TraceObject parent = objectValue.getParent();
		return parent != null &&
			parent.getTargetSchema().getInterfaces().contains(TargetRegister.class) &&
			TargetRegister.VALUE_ATTRIBUTE_NAME.equals(objectValue.getEntryKey());
	}

	public void onValueCreatedCheckTransfer(TraceObjectValue objectValue) {
		if (isRegisterValue(objectValue)) {
			try {
				onValueCreatedTransfer(objectValue);
			}
			catch (RegisterValueException e) {
				Msg.error(this, e.getMessage());
			}
		}
	}

	public void onSymbolAddedCheckTransferToLabel(TraceLabelSymbol label, boolean isBigEndian) {
		TraceObjectManager objectManager = label.getTrace().getObjectManager();
		TargetObjectSchema schema = objectManager.getRootSchema();
		if (schema == null) {
			return;
		}
		PathMatcher matcher = schema.searchFor(TargetRegister.class, true);
		matcher = matcher.applyKeys(Align.RIGHT, List.of(label.getName()));
		for (TraceObjectValPath path : it(
			objectManager.getValuePaths(label.getLifespan(), matcher))) {
			Object regRaw = path.getDestinationValue(objectManager.getRootObject());
			if (regRaw instanceof TraceObject regObj) {
				transferRegisterObjectToLabel(regObj, label, isBigEndian);
			}
		}
	}

	public void onSymbolAddedCheckTransfer(TraceSymbol symbol) {
		TraceObject root = symbol.getTrace().getObjectManager().getRootObject();
		if (root == null) {
			return;
		}
		if (symbol instanceof TraceLabelSymbol label) {
			TraceNamespaceSymbolView namespaces = label.getTrace().getSymbolManager().namespaces();
			TraceNamespaceSymbol regMapBE =
				namespaces.getGlobalNamed(InternalTracePlatform.REG_MAP_BE);
			TraceNamespaceSymbol regMapLE =
				namespaces.getGlobalNamed(InternalTracePlatform.REG_MAP_LE);
			if (label.getParentNamespace() == regMapBE) {
				onSymbolAddedCheckTransferToLabel(label, true);
			}
			else if (label.getParentNamespace() == regMapLE) {
				onSymbolAddedCheckTransferToLabel(label, false);
			}
		}
	}

	public void onSpaceAddedCheckTransfer(Trace trace, AddressSpace space) {
		TraceObject root = trace.getObjectManager().getRootObject();
		if (root == null) {
			return;
		}
		assert space.isOverlaySpace();
		if (!space.isRegisterSpace()) {
			return;
		}
		TraceMemorySpace mem = trace.getMemoryManager().getMemorySpace(space, true);
		TraceObject regContainer = trace.getObjectManager()
				.getObjectByCanonicalPath(
					TraceObjectKeyPath.parse(mem.getAddressSpace().getName()));
		if (regContainer == null || !regContainer.getTargetSchema()
				.getInterfaces()
				.contains(TargetRegisterContainer.class)) {
			return;
		}
		TracePlatformManager platformManager = trace.getPlatformManager();
		onSpaceAddedCheckTransferToPlatformRegisters(platformManager.getHostPlatform(),
			regContainer, mem);
		for (TraceGuestPlatform platform : platformManager.getGuestPlatforms()) {
			onSpaceAddedCheckTransferToPlatformRegisters(platform, regContainer, mem);
		}
	}

	protected void onMappingAddedCheckTransferRegisterObjectMemoryMapped(TraceObject registerObject,
			TraceGuestPlatformMappedRange mapped) {
		String name = getRegisterName(registerObject);
		TraceGuestPlatform guest = mapped.getGuestPlatform();
		Register register = guest.getLanguage().getRegister(name);
		// TODO: Permit overlay spaces?
		if (register == null || mapped.getGuestRange().contains(register.getAddress())) {
			return;
		}
		Address hostAddr = mapped.mapGuestToHost(register.getAddress());
		if (hostAddr == null) {
			return;
		}
		TraceMemorySpace mem = registerObject.getTrace()
				.getMemoryManager()
				.getMemorySpace(hostAddr.getAddressSpace(), true);
		for (TraceObjectValue registerValue : it(registerObject.getOrderedValues(Lifespan.ALL,
			TargetRegister.VALUE_ATTRIBUTE_NAME, true))) {
			transferValueToPlatformRegister(registerValue, guest, mem, register);
		}
	}

	public void onMappingAddedCheckTransferMemoryMapped(TraceObject root,
			TraceGuestPlatformMappedRange mapped) {
		for (TraceObjectValPath path : it(
			root.querySuccessorsTargetInterface(Lifespan.ALL, TargetRegister.class))) {
			TraceObject registerObject = path.getDestination(root);
			onMappingAddedCheckTransferRegisterObjectMemoryMapped(registerObject, mapped);
		}
	}

	public void onMappingAddedCheckTransfer(TraceGuestPlatformMappedRange mapped) {
		Trace trace = mapped.getHostPlatform().getTrace();
		TraceObject root = trace.getObjectManager().getRootObject();
		if (root == null) {
			return;
		}
		AddressSpace guestSpace = mapped.getGuestRange().getAddressSpace();
		if (guestSpace.isRegisterSpace()) {
			// TODO: Optimize: create/use TraceAddressFactory.getOverlaySpaces()
			for (AddressSpace space : trace.getBaseAddressFactory().getAllAddressSpaces()) {
				if (!space.isOverlaySpace()) {
					continue;
				}
				onSpaceAddedCheckTransfer(trace, space);
			}
		}
		else if (guestSpace.isMemorySpace()) {
			if (guestSpace.isOverlaySpace()) {
				return;
			}
			onMappingAddedCheckTransferMemoryMapped(root, mapped);
		}
		else {
			throw new AssertionError();
		}
	}

	public void processEvent(TraceChangeRecord<?, ?> event) {
		HANDLER.handleTraceChangeRecord(event);
	}

	private void objectValueCreated(TraceObjectValue objectValue) {
		onValueCreatedCheckTransfer(objectValue);
	}

	private void symbolAdded(TraceSymbol symbol) {
		onSymbolAddedCheckTransfer(symbol);
	}

	private void spaceAdded(Trace trace, AddressSpace isNull, AddressSpace space) {
		onSpaceAddedCheckTransfer(trace, space);
	}

	private void guestMappingAdded(TraceGuestPlatform guest, TraceGuestPlatformMappedRange isNull,
			TraceGuestPlatformMappedRange mapped) {
		onMappingAddedCheckTransfer(mapped);
	}
}
