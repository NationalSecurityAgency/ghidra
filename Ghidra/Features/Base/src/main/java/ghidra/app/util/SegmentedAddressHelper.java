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
package ghidra.app.util;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;

/**
 * Utility class for working with segmented addresses and segment registers.
 * Provides methods to resolve immediate operands using segment register values
 * in segmented memory architectures. This implementation is processor-neutral
 * and uses the constresolve register defined in the processor specification.
 */
public class SegmentedAddressHelper {

	/**
	 * Creates a segmented address from an immediate value using the processor's 
	 * constresolve register (defined in the processor specification).
	 * This is useful for resolving immediate operands like 0x4f0 to segment:0x4f0 addresses.
	 * 
	 * @param program the program containing the address
	 * @param contextAddress the address for getting segment register context
	 * @param segSpace the segmented address space
	 * @param immediateValue the immediate value to be used as offset
	 * @return segmented address or null if segment register unavailable
	 */
	public static Address createSegmentedAddress(Program program, Address contextAddress,
			SegmentedAddressSpace segSpace, long immediateValue) {
		
		// Get the constresolve register from the processor specification
		Register segmentRegister = getConstResolveRegister(program, segSpace);
		if (segmentRegister == null) {
			// Fallback: treat as linear address if no constresolve register defined
			return segSpace.getAddress(immediateValue);
		}
		
		return createSegmentedAddress(program, contextAddress, segSpace, 
			segmentRegister, immediateValue);
	}

	/**
	 * Creates a segmented address from an immediate value using the specified segment register.
	 * This is useful for resolving immediate operands like 0x4f0 to DS:0x4f0 addresses.
	 * 
	 * @param program the program containing the address
	 * @param contextAddress the address for getting segment register context
	 * @param segSpace the segmented address space
	 * @param segmentRegister the segment register to use
	 * @param immediateValue the immediate value to be used as offset
	 * @return segmented address or null if segment register unavailable
	 */
	public static Address createSegmentedAddress(Program program, Address contextAddress,
			SegmentedAddressSpace segSpace, Register segmentRegister, long immediateValue) {
		try {
			ProgramContext context = program.getProgramContext();
			
			if (segmentRegister != null) {
				BigInteger segValue = context.getValue(segmentRegister, contextAddress, false);
				if (segValue != null) {
					// Create segmented address: segment:immediateValue
					int segment = segValue.intValue();
					int offset = (int) (immediateValue & 0xFFFF);
					return segSpace.getAddress(segment, offset);
				}
			}
			
			// Fallback: treat as linear address if segment register unavailable
			return segSpace.getAddress(immediateValue);
		}
		catch (Exception e) {
			// Fallback to linear address on any error
			return segSpace.getAddress(immediateValue);
		}
	}

	/**
	 * Gets the constresolve register from the processor specification.
	 * This is the register defined in the <constresolve> directive of the segmentop.
	 * 
	 * @param program the program containing the language specification
	 * @param segSpace the segmented address space
	 * @return the Register object or null if not defined
	 */
	private static Register getConstResolveRegister(Program program, SegmentedAddressSpace segSpace) {
		try {
			// Get the p-code inject library from the compiler spec
			PcodeInjectLibrary injectLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			
			// Look for the segment_pcode payload which contains constresolve information
			InjectPayload segmentPayload = injectLibrary.getPayload(InjectPayload.EXECUTABLEPCODE_TYPE, "segment_pcode");
			
			if (segmentPayload instanceof InjectPayloadSegment) {
				InjectPayloadSegment segPayload = (InjectPayloadSegment) segmentPayload;
				
				// Access the constresolve register information via reflection
				// (Since the fields are private, we need to use reflection)
				java.lang.reflect.Field spaceField = InjectPayloadSegment.class.getDeclaredField("constResolveSpace");
				java.lang.reflect.Field offsetField = InjectPayloadSegment.class.getDeclaredField("constResolveOffset");
				java.lang.reflect.Field sizeField = InjectPayloadSegment.class.getDeclaredField("constResolveSize");
				
				spaceField.setAccessible(true);
				offsetField.setAccessible(true);
				sizeField.setAccessible(true);
				
				AddressSpace constResolveSpace = (AddressSpace) spaceField.get(segPayload);
				long constResolveOffset = offsetField.getLong(segPayload);
				int constResolveSize = sizeField.getInt(segPayload);
				
				if (constResolveSpace != null) {
					// Find the register at this address
					Address regAddress = constResolveSpace.getAddress(constResolveOffset);
					return program.getLanguage().getRegister(regAddress, constResolveSize);
				}
			}
		}
		catch (Exception e) {
			// Ignore errors and fall through to null
		}
		
		return null;
	}

	/**
	 * Creates a segmented address using the Data Segment register (processor-specific).
	 * This method uses the processor's constresolve register automatically.
	 * 
	 * @param program the program containing the address
	 * @param contextAddress the address for getting segment register context
	 * @param segSpace the segmented address space
	 * @param immediateValue the immediate value to be used as offset
	 * @return segmented address using the appropriate segment register
	 */
	public static Address createDataSegmentAddress(Program program, Address contextAddress,
			SegmentedAddressSpace segSpace, long immediateValue) {
		return createSegmentedAddress(program, contextAddress, segSpace, immediateValue);
	}

	/**
	 * Gets the current value of a segment register at the specified address.
	 * 
	 * @param program the program containing the address
	 * @param contextAddress the address for getting segment register context
	 * @param segmentRegisterName the name of the segment register (e.g., "DS", "ES", "CS")
	 * @return segment register value or null if unavailable
	 */
	public static BigInteger getSegmentRegisterValue(Program program, Address contextAddress,
			String segmentRegisterName) {
		try {
			ProgramContext context = program.getProgramContext();
			Register segRegister = context.getRegister(segmentRegisterName);
			
			if (segRegister != null) {
				return context.getValue(segRegister, contextAddress, false);
			}
		}
		catch (Exception e) {
			// ignore
		}
		return null;
	}

	/**
	 * Checks if the given address space is a segmented address space.
	 * 
	 * @param addressSpace the address space to check
	 * @return true if the address space is segmented
	 */
	public static boolean isSegmentedAddressSpace(ghidra.program.model.address.AddressSpace addressSpace) {
		return addressSpace instanceof SegmentedAddressSpace;
	}
} 