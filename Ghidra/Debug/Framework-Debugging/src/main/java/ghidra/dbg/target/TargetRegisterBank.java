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
package ghidra.dbg.target;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.error.DebuggerRegisterAccessException;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.util.Msg;

/**
 * A bank of registers on the debug target
 * 
 * <p>
 * The bank allows access to registers' <em>values</em>; whereas, a {@link TargetRegisterContainer}
 * allows reflection of the registers' names and structures.
 */
@DebuggerTargetObjectIface("RegisterBank")
public interface TargetRegisterBank extends TargetObject {

	String DESCRIPTIONS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "descriptions";
	// TODO: Remove this stopgap once we implement register-value replay
	String REGISTERVALS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "register_values";

	/**
	 * Get the object describing the registers in this bank
	 * 
	 * <p>
	 * TODO: {@link TargetRegisterContainer} ought to be removed. However, some models present a
	 * complex structure for their register banks and containers, splitting the set into, e.g.,
	 * User, Vector, etc. I suspect the simplest way for a client to accommodate this is to use
	 * {@link TargetObjectSchema#searchFor(Class, boolean)}, passing {@link TargetRegister}. The
	 * "canonical container" concept doesn't really work here, as that will yield each set, rather
	 * than the full descriptions container.
	 * 
	 * @return a future which completes with object
	 */
	@TargetAttributeType(name = DESCRIPTIONS_ATTRIBUTE_NAME)
	public default TargetRegisterContainer getDescriptions() {
		return getTypedAttributeNowByName(DESCRIPTIONS_ATTRIBUTE_NAME,
			TargetRegisterContainer.class, null);
	}

	/**
	 * Read the given registers
	 * 
	 * <p>
	 * The value of each register is given as a byte array in big-endian order, <em>no matter the
	 * byte order of the target platform</em>.
	 * 
	 * <p>
	 * <b>WARNING:</b> the implementation is not required to have any understanding of the register
	 * structure. In particular, caches are not aware of child registers. To avoid the issue, it is
	 * highly recommended to only read and write base registers.
	 * 
	 * @param registers the registers to read
	 * @return a future which completes with a name-value map of the values read
	 */
	public default CompletableFuture<? extends Map<String, byte[]>> readRegisters(
			Collection<TargetRegister> registers) {
		return readRegistersNamed(
			registers.stream().map(TargetRegister::getIndex).collect(Collectors.toSet()));
	}

	/**
	 * Write the given registers
	 * 
	 * <p>
	 * The value of each register is given as a byte array in big-endian order, <em>no matter the
	 * byte order of the target platform</em>.
	 * 
	 * <p>
	 * <b>WARNING:</b> the implementation is not required to have any understanding of the register
	 * structure. In particular, caches are not aware of child registers. To avoid the issue, it is
	 * highly recommended to only read and write base registers.
	 * 
	 * @param values the register-value map to write
	 * @return a future which completes upon successfully writing all given registers
	 */
	public default CompletableFuture<Void> writeRegisters(Map<TargetRegister, byte[]> values) {
		Map<String, byte[]> named = new LinkedHashMap<>();
		for (Entry<TargetRegister, byte[]> ent : values.entrySet()) {
			named.put(ent.getKey().getIndex(), ent.getValue());
		}
		return writeRegistersNamed(named);
	}

	/**
	 * Read the named registers
	 * 
	 * @see #readRegisters(Collection)
	 * @param names the names of registers to read
	 * @return a future which completes with a name-value map of the values read
	 * @throws DebuggerRegisterAccessException if a named register does not exist
	 */
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names);

	/**
	 * Write the named registers
	 * 
	 * @see #writeRegistersNamed(Map)
	 * @param values the name-value map to write
	 * @return a future which completes upon successfully writing all given registers
	 * @throws DebuggerRegisterAccessException if a named register does not exist
	 */
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values);

	/**
	 * Read the named registers
	 * 
	 * @see #readRegistersNamed(Collection)
	 */
	public default CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			String... names) {
		return readRegistersNamed(List.of(names));
	}

	/**
	 * Read the given register
	 * 
	 * @see #readRegisters(Collection)
	 * @param register the register to read
	 * @return a future which completes with the value read
	 */
	public default CompletableFuture<byte[]> readRegister(TargetRegister register) {
		return readRegister(register.getIndex());
	}

	/**
	 * Write the given register
	 * 
	 * @see #writeRegistersNamed(Map)
	 * @param register the register to write
	 * @param value the value to write
	 * @return a future which completes upon successfully writing the register
	 */
	public default CompletableFuture<Void> writeRegister(TargetRegister register, byte[] value) {
		return writeRegistersNamed(Map.of(register.getIndex(), value));
	}

	/**
	 * Read the named register
	 * 
	 * @see #readRegisters(Collection)
	 * @param name the name of the register to read
	 * @return a future which completes with the value read
	 */
	public default CompletableFuture<byte[]> readRegister(String name) {
		return readRegistersNamed(List.of(name)).thenApply(m -> m.get(name));
	}

	/**
	 * Write the named register
	 * 
	 * @see #writeRegistersNamed(Map)
	 * @param name the name of the register to write
	 * @param value the value to write
	 * @return a future which completes upon successfully writing the register
	 */
	public default CompletableFuture<Void> writeRegister(String name, byte[] value) {
		return writeRegistersNamed(Map.of(name, value));
	}

	/**
	 * Get a view of the locally-cached register values, if available
	 * 
	 * <p>
	 * If caching is not done locally, this returns the empty map.
	 * 
	 * @return the cached register values
	 */
	public default Map<String, byte[]> getCachedRegisters() {
		return Map.of();
	}

	/**
	 * Clear the register cache
	 * 
	 * <p>
	 * To avoid duplicate requests for the same registers, proxies are encouraged to implement a
	 * write-through register cache. If the proxy does so, then calling this method must flush that
	 * cache. If no cache is used, then no action is necessary.
	 * 
	 * @deprecated Override {@link #invalidateCaches()} instead
	 */
	@Deprecated
	public default void clearRegisterCache() {
		invalidateCaches().exceptionally(e -> {
			Msg.error(this, "Error clearing register caches");
			return null;
		});
	}
}
