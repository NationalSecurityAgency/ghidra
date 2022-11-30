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
package ghidra.trace.model.guest;

import java.util.List;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.trace.model.target.TraceObject;

/**
 * A platform within a trace
 * 
 * <p>
 * Traces can model systems where multiple processors or languages are involved. Every trace has a
 * "host" platform. There may also be zero or more "guest" platforms. The guest platforms' memories
 * and registers must be mapped into the host platform to be used in the trace. This class provides
 * access to the properties of a platform and a mechanisms for translating addresses between this
 * and the host platform. If this is the host platform, the translation methods are the identity
 * function.
 */
public interface TracePlatform {

	/**
	 * Get the trace
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Check if this is a guest platform
	 * 
	 * @return true for guest, false for host
	 */
	boolean isGuest();

	/**
	 * Check if this is the host platform
	 * 
	 * @return true for host, false for guest
	 */
	default boolean isHost() {
		return !isGuest();
	}

	/**
	 * Get the language of the guest platform
	 * 
	 * @return the language
	 */
	Language getLanguage();

	/**
	 * Get the address factory of the guest platform
	 * 
	 * @return the factory
	 */
	default AddressFactory getAddressFactory() {
		return getLanguage().getAddressFactory();
	}

	/**
	 * Get the compiler of the guest platform
	 * 
	 * @return the compiler spec
	 */
	CompilerSpec getCompilerSpec();

	/**
	 * Get the addresses in the host which are mapped to somewhere in the guest
	 * 
	 * @return the address set
	 */
	AddressSetView getHostAddressSet();

	/**
	 * Get the addresses in the guest which are mapped to somehere in the host
	 * 
	 * @return the address set
	 */
	AddressSetView getGuestAddressSet();

	/**
	 * Translate an address from host to guest
	 * 
	 * @param hostAddress the host address
	 * @return the guest address
	 */
	Address mapHostToGuest(Address hostAddress);

	/**
	 * Translate a range from host to guest
	 * 
	 * <p>
	 * The entire range must be mapped to a single range.
	 * 
	 * @param hostRange the host range
	 * @return the guest range
	 */
	AddressRange mapHostToGuest(AddressRange hostRange);

	/**
	 * Translate a set from host to guest
	 * 
	 * <p>
	 * Only those ranges (or parts of ranges) that mapped are included.
	 * 
	 * @param hostSet the host set
	 * @return the guest set
	 */
	AddressSetView mapHostToGuest(AddressSetView hostSet);

	/**
	 * Translate an address from guest to host
	 * 
	 * @param guestAddress the guest address
	 * @return the host address
	 */
	Address mapGuestToHost(Address guestAddress);

	/**
	 * Translate a range from guest to host
	 * 
	 * <p>
	 * The entire range must be mapped to a single range.
	 * 
	 * @param guestRange the guest range
	 * @return the host range
	 */
	AddressRange mapGuestToHost(AddressRange guestRange);

	/**
	 * Translate a set from guest to host
	 * 
	 * <p>
	 * Only those ranges (or parts of ranges) that mapped are included.
	 * 
	 * @param guestSet the guest set
	 * @return the host set
	 */
	AddressSetView mapGuestToHost(AddressSetView guestSet);

	/**
	 * Translate the given platform register to the given host overlay space
	 * 
	 * @param overlay the overlay space, usually that allocated for a thread or frame
	 * @param register the platform register
	 * @return the host range
	 */
	AddressRange getConventionalRegisterRange(AddressSpace overlay, Register register);

	/**
	 * Get the name or index of the register object for the given platform register
	 * 
	 * <p>
	 * This will check for a label in the host physical space, allowing a mapper to specify an
	 * alternative register object name. See {@link #addRegisterMapOverride(Register, String)}.
	 * 
	 * @param register the platform register
	 * @return the mapped name
	 */
	String getConventionalRegisterObjectName(Register register);

	/**
	 * Get the expected path where an object defining the register value would be
	 * 
	 * @param schema the schema of the register container
	 * @param path the path to the register container
	 * @param name the name of the register on the target
	 * @return the path matcher, possibly empty
	 */
	PathMatcher getConventionalRegisterPath(TargetObjectSchema schema, List<String> path,
			String name);

	/**
	 * Get the expected path where an object defining the register value would be
	 * 
	 * <p>
	 * This will check for a label in the host physical space, allowing a mapper to specify an
	 * alternative register object name. See {@link #addRegisterMapOverride(Register, String)}.
	 * 
	 * @param schema the schema of the register container
	 * @param path the path to the register container
	 * @param register the platform register
	 * @return the path matcher, possibly empty
	 */
	PathMatcher getConventionalRegisterPath(TargetObjectSchema schema, List<String> path,
			Register register);

	/**
	 * Get the expected path where an object defining the register value would be
	 * 
	 * @see #getConventionalRegisterPath(TargetObjectSchema, List, Register)
	 * @param container the register container
	 * @param register the platform register
	 * @return that path matcher, possibly empty, or null if the trace has no root schema
	 */
	PathMatcher getConventionalRegisterPath(TraceObject container, Register register);

	/**
	 * Get the expected path where an object defining the register value would be
	 * 
	 * @see #getConventionalRegisterPath(TargetObjectSchema, List, Register)
	 * @param container the target register container
	 * @param register the platform register
	 * @return the path matcher, possibly empty
	 */
	PathMatcher getConventionalRegisterPath(TargetObject container, Register register);

	/**
	 * Get the expected path where an object defining the register value would be
	 *
	 * @see #getConventionalRegisterPath(TargetObjectSchema, List, Register)
	 * @param overlay the overlay space allocated for a thread or frame
	 * @param register the platform register
	 * @return the path matcher, or null if there is no root schema
	 */
	PathMatcher getConventionalRegisterPath(AddressSpace overlay, Register register);

	/**
	 * Add a label the conventionally maps the value of a {@link TargetRegister} in the object
	 * manager to a register from this platform
	 * 
	 * @param register the language register
	 * @param objectName the name of the {@link TargetRegister} in the object tree
	 * @return the label
	 */
	TraceLabelSymbol addRegisterMapOverride(Register register, String objectName);

	/**
	 * Get a memory buffer, which presents the host bytes in the guest address space
	 * 
	 * <p>
	 * This, with pseudo-disassembly, is the primary mechanism for adding instructions in the guest
	 * language.
	 * 
	 * @param snap the snap, up to which the most recent memory changes are presented
	 * @param guestAddress the starting address in the guest space
	 * @return the mapped memory buffer
	 */
	MemBuffer getMappedMemBuffer(long snap, Address guestAddress);

	/**
	 * Copy the given instruction set, but with addresses mapped from the guest space to the host
	 * space
	 * 
	 * <p>
	 * Instructions which do not map are silently ignored. If concerned, the caller ought to examine
	 * the resulting instruction set and/or the resulting address set after it is added to the
	 * trace. A single instruction cannot span two mapped ranges, even if the comprised bytes are
	 * consecutive in the guest space. Mapping such an instruction back into the host space would
	 * cause the instruction to be split in the middle, which is not possible. Thus, such
	 * instructions are silently ignored.
	 * 
	 * @param set the instruction set in the guest space
	 * @return the instruction set in the host space
	 */
	InstructionSet mapGuestInstructionAddressesToHost(InstructionSet set);
}
