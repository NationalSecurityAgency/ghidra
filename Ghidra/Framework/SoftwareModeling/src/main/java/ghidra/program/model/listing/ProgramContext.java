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
package ghidra.program.model.listing;

import java.math.BigInteger;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

/**
 * Interface to define a processor register context over the address space.
 */
public interface ProgramContext {

	/**
	 * @return true if one or more non-flowing context registers fields
	 * have been defined within the base processor context register.
	 */
	public boolean hasNonFlowingContext();

	/**
	 * Modify register value to eliminate non-flowing bits
	 * @param value register value to be modified
	 * @return value suitable for flowing
	 */
	public RegisterValue getFlowValue(RegisterValue value);

	/**
	 * Modify register value to only include non-flowing bits
	 * @param value register value to be modified
	 * @return new value or null
	 */
	public RegisterValue getNonFlowValue(RegisterValue value);

	/**
	 * Get a Register object given the name of a register
	 *
	 * @param name the name of the register.
	 * @return The register with the given name or null if no register has that name.
	 */
	public Register getRegister(String name);

	/**
	 * Get all the register descriptions defined for this program context.
	 *
	 * @return unmodifiable list of defined register descriptions
	 */
	public List<Register> getRegisters();

	/**
	 * Returns an array of all registers that at least one value associated with an address.
	 * @return a array of all registers that at least one value associated with an address.
	 */
	public Register[] getRegistersWithValues();

	/**
	 * Returns the value assigned to a register at a given address.  This method will return any
	 * default value assigned to the register at the given address if no explicit value has been set
	 * at that address.
	 * @param register the register for which to get its value.
	 * @param address the address at which to get a value.
	 * @param signed if true, interprets the fix-bit size register value as a signed value.  
	 * @return a BigInteger object containing the value of the registe at the given address or null
	 * if no value has been assigned.
	 */
	public BigInteger getValue(Register register, Address address, boolean signed);

	/**
	 * Returns a register value and mask for the given register.
	 * @param register the register
	 * @param address  the address of the value
	 * @return a register value and mask for the given register
	 */
	public RegisterValue getRegisterValue(Register register, Address address);

	/**
	 * Sets the register context over the given range to the given value.
	 * @param start   the start address to set values
	 * @param end     the end address to set values
	 * @param value   the actual values to store at address
	 * @throws ContextChangeException if failed to modifiy context across specified range 
	 * (e.g., instruction exists).
	 */
	public void setRegisterValue(Address start, Address end, RegisterValue value)
			throws ContextChangeException;

	/**
	 * Returns the (non-default)value assigned to a register at a given address.
	 * @param register the register for which to get its value.
	 * @param address the address at which to get a value. 
	 * @return a RegisterValue object containing the value of the register at the given address or 
	 * possibly null if no value has been assigned.
	 */
	public RegisterValue getNonDefaultValue(Register register, Address address);

	/**
	 * Associates a value with a register over a given address range. Any previous values will be
	 * overwritten.
	 * @param register the register for which to assign a value.
	 * @param start the start address.
	 * @param end the end address (inclusive).
	 * @param value the value to assign.  A value of null will effective clear any existing values.
	 * @throws ContextChangeException if failed to modifiy context across specified range 
	 * (e.g., instruction exists).
	 */
	public void setValue(Register register, Address start, Address end, BigInteger value)
			throws ContextChangeException;

	/**
	 * Returns an AddressRangeIterator over all addresses that have an associated value for the given 
	 * register.  Each range returned will have the same value associated with the register for all 
	 * addresses in that range.
	 * @param register the register for which to get set value ranges.
	 * @return An AddressRangeIterator over all address that have values for the given register.
	 */
	public AddressRangeIterator getRegisterValueAddressRanges(Register register);

	/**
	 * Returns an AddressRangeIterator over all addresses that have an associated value within the
	 * given range for the given register.  Each range returned will have the same value
	 * associated with the register for all addresses in that range.
	 * @param register the register for which to get set value ranges.
	 * @param start start of address range to search
	 * @param end end of address range to search
	 * @return An AddressRangeIterator over all address within the given range that have values
	 *  for the given register.
	 */
	public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
			Address end);

	/**
	 * Returns the bounding address-range containing addr and the the same RegisterValue throughout.
	 * The range returned may be limited by other value changes associated with register's base-register.
	 * @param register program register
	 * @param addr program address
	 * @return single register-value address-range containing addr
	 */
	public AddressRange getRegisterValueRangeContaining(Register register, Address addr);

	/**
	 * Returns an AddressRangeIterator over all addresses that have an associated default value for the given 
	 * register.  Each range returned will have the same default value associated with the register for all 
	 * addresses in that range.
	 * @param register the register for which to get set default value ranges.
	 * @return An AddressRangeIterator over all address that have default values for the given register.
	 */
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register);

	/**
	 * Returns an AddressRangeIterator over all addresses that have an associated default value within the
	 * given range for the given register.  Each range returned will have the same default value
	 * associated with the register for all addresses in that range.
	 * @param register the register for which to get default value ranges.
	 * @param start start of address range to search
	 * @param end end of address range to search
	 * @return An AddressRangeIterator over all address within the given range that have default values
	 *  for the given register.
	 */
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
			Address start, Address end);

	/**
	 * Gets the registers for this context that are used for processor context states.
	 * @return all processor context registers
	 */
	public List<Register> getContextRegisters();

	/**
	 * Remove (unset) the register values for a given address range.
	 * @param start starting address.
	 * @param end ending adddress.
	 * @param register handle to the register to be set.
	 * @throws ContextChangeException thrown if context change not permitted over specified 
	 * range (e.g., instructions exist)
	 */
	public void remove(Address start, Address end, Register register) throws ContextChangeException;

	/**
	 * Get an alphabetical sorted unmodifiable list of original register names 
	 * (including context registers).  Names correspond to orignal register
	 * name and not aliases which may be defined.
	 * 
	 * @return alphabetical sorted unmodifiable list of original register names.
	 */
	public List<String> getRegisterNames();

	/**
	 * Returns true if the given register has the value over the addressSet
	 * @param reg the register whose value is to be tested.
	 * @param value the value to test for.
	 * @param addrSet the set of addresses to test
	 * @return true if every address in the addrSet has the value.
	 */
	public boolean hasValueOverRange(Register reg, BigInteger value, AddressSetView addrSet);

	/**
	 * Returns the default value of a register at a given address.
	 * @param register the register for which to get a default value.
	 * @param address the address at which to get a default value.
	 * @return the default value of the register at the given address or null if no default value
	 * has been assigned.
	 */
	public RegisterValue getDefaultValue(Register register, Address address);

	/**
	 * Returns the base context register.
	 * @return the base context register.
	 */
	public Register getBaseContextRegister();

	/**
	 * @return Get the current default disassembly context to be used when initiating disassmbly
	 */
	public RegisterValue getDefaultDisassemblyContext();

	/**
	 * Set the initial disassembly context to be used when initiating disassmbly
	 * @param value context register value
	 */
	public void setDefaultDisassemblyContext(RegisterValue value);

	/**
	 * Get the disassembly context for a specified address.  This context is formed
	 * from the default disassembly context and the context register value stored
	 * at the specified address.  Those bits specified by the stored context value
	 * take precedence.
	 * @param address program address
	 * @return disassembly context register value
	 */
	public RegisterValue getDisassemblyContext(Address address);
}
