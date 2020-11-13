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
package ghidra.program.disassemble;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;
import java.util.*;

/**
 * Maintains processor state information during disassembly and analysis.  Tracks register state 
 * associated with instruction flows.  Within this context, a flow is defined as a contiguous
 * range of instructions.  Also, this context provides storage for context states at future flow
 * addresses, which will be used when subsequent flowTo(Address) or flowStart(Address) calls 
 * are made with those addresses.
 */
public class DisassemblerContextImpl implements DisassemblerContext {

	private ProgramContext programContext;
	private Address startAddr;
	private Address contextChangePoint;
	private Address currentAddress;
	private Register contextRegister;

	/**
	 * Active context register state for the current flow location.
	 */
	private RegisterValue contextRegisterValue;

	/**
	 * Delayed context register state for the current flow location.
	 * Set only if context value changed for current flow location
	 */
	private RegisterValue delayedContextRegisterValue;

	/**
	 * Noflow context-register value which repeats until the next contextChangePoint
	 */

// TODO: Need to decide when previously stored context (flow & non-flow bits) should be
// used during disassembly.  This must be done carefully since it would seem we should
// always give precedence to any flow/future context determined during disassembly 

	private RegisterValue repeatedNoflowValue;

	/**
	 * Active Register context values for the current flow location.
	 * NOTE: default register values are never included within this state.
	 * This map is not used for storing the context register
	 * @see #contextRegisterValue
	 */
	private Map<Register, RegisterValue> registerStateMap;

	/**
	 * Future Register context values for specific flow starting locations when
	 * the flowFrom address is NO_ADDRESS.
	 * 
	 * A flow from address of NO_ADDRESS is used when it doesn't matter from where
	 * the flow originates.
	 * 
	 * NOTE: default register values are never included within this future state
	 */
	private Map<Address, Map<Register, RegisterValue>> noAddressFutureRegisterStateMap;

	/**
	 * Future RegisterStateMaps from a given flow with a given flowing address.
	 *    Address.NO_ADDRESS is used as the flow from if there is no flow from.
	 * NOTE: default register values are never included within this future state
	 */
	private Map<Address, Map<Address, Map<Register, RegisterValue>>> futureFlowRegisterStateMaps;
	
	/**
	 * Constructor for DisassemblerContext.
	 * @param programContext contains the values for registers at specific addresses store in the program.
	 */
	public DisassemblerContextImpl(ProgramContext programContext) {
		this.programContext = programContext;
		this.contextRegister = programContext.getBaseContextRegister();
// TODO: Can contextRegister be null ??
		contextRegisterValue = new RegisterValue(contextRegister);
		registerStateMap = new HashMap<Register, RegisterValue>();

		futureFlowRegisterStateMaps = new HashMap<Address, Map<Address, Map<Register, RegisterValue>>>();
		
		// add a flow for the default Address.NO_ADDRESS
		noAddressFutureRegisterStateMap = new HashMap<Address, Map<Register, RegisterValue>>();
		futureFlowRegisterStateMaps.put(Address.NO_ADDRESS, noAddressFutureRegisterStateMap);
	}

	public ProgramContext getProgramContext() {
		return programContext;
	}

	@Override
	public Register getBaseContextRegister() {
		return contextRegister;
	}

	/**
	 * Saves the current processor state for when this context flows to the given address.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param address the address at which to save the current processor state.
	 * @return context register value which was copied
	 */
	public RegisterValue copyToFutureFlowState(Address address) {
		return copyToFutureFlowState(Address.NO_ADDRESS, address);
	}
	
	/**
	 * Saves the current processor state flowing from the fromAddr, for when this context flows to the given address.
	 *
	 * @param fromAddr the address from which this flow originates.
	 * @param destAddr the address at which to save the current processor state.
	 * @return context register value which was copied
	 */
	public RegisterValue copyToFutureFlowState(Address fromAddr, Address destAddr) {
		if (destAddr.equals(currentAddress)) {
			return contextRegisterValue;
		}
		// give precedence to any future context set explicitly during instruction parse 
		RegisterValue flowValue =
			programContext.getFlowValue(delayedContextRegisterValue != null ? delayedContextRegisterValue
					: contextRegisterValue);
		setRegisterValue(fromAddr, destAddr, flowValue, false);

		Iterator<Register> it = registerStateMap.keySet().iterator();
		while (it.hasNext()) {
			Register reg = it.next();
			RegisterValue value = registerStateMap.get(reg);
			setRegisterValue(fromAddr, destAddr, value, false);
		}
		return flowValue;
	}

	/**
	 * Saves the current processor state for when this context is later used at the given address.
	 * If the address already has a value, return the value on a collision list!
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param address the address at which to save the current processor state.
	 */
	public ArrayList<RegisterValue> mergeToFutureFlowState(Address address) {
		return mergeToFutureFlowState(Address.NO_ADDRESS, address);
	}

	/**
	 * Saves the current processor state flowing from the fromAddr to the destAddr for when this context is later used.
	 * If the address already has a value, return the value on a collision list!
	 * 
	 * @param fromAddr the address from which this flow originated
	 * @param destAddr the address at which to save the current processor state.
	 */
	public ArrayList<RegisterValue> mergeToFutureFlowState(Address fromAddr, Address destAddr) {
		ArrayList<RegisterValue> collisionList = new ArrayList<RegisterValue>();
		if (destAddr.equals(currentAddress)) {
			return collisionList;
		}
		setRegisterValue(fromAddr, destAddr, programContext.getFlowValue(contextRegisterValue), false);

		Iterator<Register> it = registerStateMap.keySet().iterator();
		while (it.hasNext()) {
			Register reg = it.next();
			RegisterValue value = registerStateMap.get(reg);
			RegisterValue curValue = getRegisterValue(reg, fromAddr, destAddr);
			// check if there already is a value
			if (curValue != null && !value.equals(curValue)) {
				collisionList.add(value);
			}
			setRegisterValue(fromAddr, destAddr, value, false);
		}

		return collisionList;
	}

	/**
	 * Terminate active flow while preserving any accumulated future context.
	 * Any context commits resulting from a flowToAddress or flowEnd will be 
	 * unaffected.
	 */
	public void flowAbort() {
		if (!isFlowActive()) {
			throw new IllegalStateException("Attempted to abort a flow that was not started.");
		}
		startAddr = null;
		currentAddress = null;
	}

	/**
	 * Starts a new flow. Initializes the current state for all registers using any future flow state
	 * that has been set.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param address the starting address of a new instruction flow.
	 * @throws IllegalStateException if a previous flow was not ended.
	 */
	public void flowStart(Address address) {
		flowStart(Address.NO_ADDRESS,address);
	}

	/**
	 * Starts a new flow from an address to the new start.
	 * Initializes the current state for all registers using any future flow state
	 * that has been set flowing from the fromAddr.
	 *
	 * @param fromAddr address that this flow is flowing from.
	 * @param toAddr the starting address of a new instruction flow.
	 * @throws IllegalStateException if a previous flow was not ended.
	 */
	public void flowStart(Address fromAddr, Address toAddr) {
		if (isFlowActive()) {
			throw new IllegalStateException("Previous flow was not ended.");
		}
		startAddr = toAddr;
		currentAddress = toAddr;
		registerStateMap.clear();
		contextRegisterValue = null;
		delayedContextRegisterValue = null;
		contextChangePoint = toAddr;

		// get next context value within flow, combining current, future, previously stored and default context values
		Map<Register, RegisterValue> futureStateMap = getFutureRegisterStateMap(fromAddr, toAddr, true);
		
		if (futureStateMap != null) {
			registerStateMap = futureStateMap;
		}
		else {
			registerStateMap.clear();
		}

		contextRegisterValue = getNextContextInFlow(toAddr, futureStateMap, true);

		setNextContextChangePoint(toAddr);
	}

	/**
	 * Get flowed context value at arbitrary destination address without affecting state.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param destAddr
	 * @param isFallThrough
	 * @return the flowed context value
	 */
	public RegisterValue getFlowContextValue(Address destAddr, boolean isFallThrough) {
		return getFlowContextValue(Address.NO_ADDRESS, destAddr, isFallThrough);
	}
	
	/**
	 * Get flowed context value at a destination address, that has been flowed from the fromAddr, without affecting state.
	 *
	 * @param fromAddr address that this flow is flowing from.
	 * @param destAddr the starting address of a new instruction flow.
	 * @throws IllegalStateException if a previous flow was not ended.
	 */
	public RegisterValue getFlowContextValue(Address fromAddr, Address destAddr, boolean isFallThrough) {

		if (isFlowActive() && currentAddress.equals(destAddr)) {
			return contextRegisterValue;
		}

		RegisterValue nextContextRegisterValue = programContext.getFlowValue(contextRegisterValue); // strip non-flowing context

		// combine in any contextRegisterValue from the future flow state.
		RegisterValue futureContextRegisterValue = null;
		
		// get next context value within flow, combining current, future, previously stored and default context values
		Map<Register, RegisterValue> futureStateMap = getFutureRegisterStateMap(fromAddr, destAddr, false);
		
		if (futureStateMap != null) {
			futureContextRegisterValue = futureStateMap.get(contextRegister);
			nextContextRegisterValue =
				combineRegisterValues(nextContextRegisterValue, futureContextRegisterValue, true);
		}

		// combine any previously stored context with future state value
		RegisterValue preExistingContextRegisterValue =
			programContext.getDisassemblyContext(destAddr);
		if (isFallThrough) {
			preExistingContextRegisterValue =
				programContext.getNonFlowValue(preExistingContextRegisterValue);
		}
		nextContextRegisterValue =
			combineRegisterValues(preExistingContextRegisterValue, nextContextRegisterValue, true);

		// combine default context
		RegisterValue defaultValue = programContext.getDefaultValue(contextRegister, destAddr);
		nextContextRegisterValue =
			combineRegisterValues(defaultValue, nextContextRegisterValue, true);

		if (nextContextRegisterValue == null) {
			nextContextRegisterValue = new RegisterValue(contextRegister);
		}

		return nextContextRegisterValue;
	}

	/**
	 * Continues the current flow at the given address.  Checks for register values that have been
	 * stored in the future flow state.  If any registers have saved future state, the current state
	 * for all registers is written to the program context upto the specified address(exclusive).
	 * The future flow state values are then loaded into the current context.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param address the address to flow to.
	 * @throws IllegalStateException if no flow was started.
	 */
	public void flowToAddress(Address address) {
		flowToAddress(Address.NO_ADDRESS, address);
	}

	/**
	 * 
	 * Continues the current flow from an address to the given address.  Checks for register values that have been
	 * stored in the future flow state.  If any registers have saved future state, the current state
	 * for all registers is written to the program context upto the specified address(exclusive).
	 * The future flow state values are then loaded into the current context.
	 *
	 * @param fromAddr address that this flow is flowing from.
	 * @param destAddr the starting address of a new instruction flow.
	 * @throws IllegalStateException if a previous flow was not ended.
	 */
	public void flowToAddress(Address fromAddr, Address destAddr) {
		if (!isFlowActive()) {
			throw new IllegalStateException("Attempted to continue a flow that was not started.");
		}
		if (currentAddress.compareTo(destAddr) > 0) {
			throw new IllegalArgumentException("address must not be less than current address");
		}
		if (currentAddress.equals(destAddr)) {
			return;
		}

		currentAddress = destAddr;

		if (delayedContextRegisterValue != null &&
			!delayedContextRegisterValue.equals(contextRegisterValue)) {
			// flush current range due to delayed context change
			if (!startAddr.equals(currentAddress)) {
				saveProgramContext(startAddr, currentAddress.previous());
			}
			contextRegisterValue = delayedContextRegisterValue;
			startAddr = currentAddress;
		}

		// get next context value within flow, combining current, future, previously stored and default context values
		Map<Register, RegisterValue> futureStateMap = getFutureRegisterStateMap(fromAddr, destAddr, true);
		
		RegisterValue nextContextRegisterValue = getNextContextInFlow(destAddr, futureStateMap, false);
		delayedContextRegisterValue = null;

		// continue flowing context if no change
		if (futureStateMap == null && nextContextRegisterValue.equals(contextRegisterValue)) {
			return;
		}

		// store context to program over previous range
		if (!startAddr.equals(currentAddress)) {
			saveProgramContext(startAddr, currentAddress.previous());
		}

		// start new range using modified context
		startAddr = destAddr;
		contextRegisterValue = nextContextRegisterValue;

		// update all other registers values in current state
		if (futureStateMap != null) {
			for (Register register : futureStateMap.keySet()) {
				RegisterValue futureValue = futureStateMap.get(register);
				RegisterValue currentValue = registerStateMap.get(register);
				if (currentValue != null) {
					futureValue = currentValue.combineValues(futureValue);
				}
				registerStateMap.put(register, futureValue);
			}
		}
	}

	/**
	 * Get the future Register state map and conditionally remove the map
	 * 
	 * @param fromAddr Address flowing from
	 * @param destAddr Address flowing to
	 * @param remove true to remove the entry
	 * @return State Map or null if not found
	 */
	private Map<Register, RegisterValue> getFutureRegisterStateMap(Address fromAddr, Address destAddr, boolean remove) {
		// if we don't know the fromAddr for this flow, then just use the simple map
		//    the flow map from NO_ADDRES is always indexed on destAddr
		if (fromAddr == Address.NO_ADDRESS) {
			Map<Address, Map<Register, RegisterValue>> futureRegisterStateMap = noAddressFutureRegisterStateMap;
			
			Map<Register, RegisterValue> futureStateMap = null;
			if (remove) {
				futureStateMap = futureRegisterStateMap.remove(destAddr);
			} else {
				futureStateMap = futureRegisterStateMap.get(destAddr);
			}
			return futureStateMap;
		}

		// if we have a fromAddr for this flow, then it looks up the destAddr
		//   then looks in a sub-map to find the address we flowed from
		Map<Address, Map<Register, RegisterValue>> futureRegisterStateMap = futureFlowRegisterStateMaps.get(destAddr);
	
		Map<Register, RegisterValue> futureStateMap = null;
		if (futureRegisterStateMap != null) {
			if (remove) {
				futureStateMap = futureRegisterStateMap.remove(fromAddr);
				if (futureStateMap != null && futureStateMap.isEmpty()) {
					futureFlowRegisterStateMaps.remove(destAddr);
				}
			} else {
				futureStateMap = futureRegisterStateMap.get(fromAddr);
			}
		}
		return futureStateMap;
	}
	
	/**
	 * Lookup and if not found create a future Register flow state
	 * 
	 * @param fromAddr can be NO_ADDRESS if flow from is unknown
	 * @param destAddr future flow state destination.
	 * 
	 * @return future flow state at the destination
	 */
	private Map<Register, RegisterValue> findFutureFlowStateMap(Address fromAddr, Address destAddr) {
		Map<Register, RegisterValue> stateMap = null;
		Map<Address, Map<Register, RegisterValue>> futureRegisterStateMap = noAddressFutureRegisterStateMap;
		if (fromAddr == Address.NO_ADDRESS) {
			// for NO_ADDRESS flow from, always look up by the destAddr,

			stateMap = futureRegisterStateMap.get(destAddr);

			// didn't find a flow from map, create it
			if (stateMap == null) {
				stateMap = new HashMap<Register, RegisterValue>();
				futureRegisterStateMap.put(destAddr, stateMap);
			}
		} else {
			// for flows where the flowFrom addr is known, look up by destAddr first, then flowFrom addr
			futureRegisterStateMap = futureFlowRegisterStateMaps.get(destAddr);

			// didn't find a flow to map, create it
			if (futureRegisterStateMap == null) {
				futureRegisterStateMap = new HashMap<Address, Map<Register, RegisterValue>>();
				futureFlowRegisterStateMaps.put(destAddr,
						futureRegisterStateMap);
			} else {
				stateMap = futureRegisterStateMap.get(fromAddr);
			}

			// didn't find a flow from map, create it
			if (stateMap == null) {
				stateMap = new HashMap<Register, RegisterValue>();
				futureRegisterStateMap.put(fromAddr, stateMap);
			}
		}
		return stateMap;
	}

	/**
	 * Get next (i.e., fall-through) context register value in active flow.
	 * Internal state may be updated to track next future context change point.
	 * @param address
	 * @param futureStateMap
	 * @param startOfFlow
	 * @return
	 */
	private RegisterValue getNextContextInFlow(Address address,
			Map<Register, RegisterValue> futureStateMap, boolean startOfFlow) {

		RegisterValue contextValue = contextRegisterValue;
		if (delayedContextRegisterValue != null) {
			contextValue = combineRegisterValues(contextValue, delayedContextRegisterValue, true);
		}
		RegisterValue nextContextRegisterValue = programContext.getFlowValue(contextValue); // strip non-flowing context

		// combine in any contextRegisterValue from the future flow state.
		RegisterValue futureContextRegisterValue = null;
		if (futureStateMap != null) {
			futureContextRegisterValue = futureStateMap.remove(contextRegister);
			nextContextRegisterValue =
				combineRegisterValues(nextContextRegisterValue, futureContextRegisterValue, true);
		}

		// combine any previously stored context with future state value
		if (contextChangePoint != null && address.compareTo(contextChangePoint) >= 0) {
			RegisterValue preExistingContextRegisterValue =
				programContext.getDisassemblyContext(address);
			repeatedNoflowValue = programContext.getNonFlowValue(preExistingContextRegisterValue);
			if (!startOfFlow) {
				preExistingContextRegisterValue = repeatedNoflowValue;
			}
			nextContextRegisterValue =
				combineRegisterValues(preExistingContextRegisterValue, nextContextRegisterValue,
					true);
			setNextContextChangePoint(address);
		}
		else if (repeatedNoflowValue != null && repeatedNoflowValue.hasAnyValue()) {
			// combine any repeated noflow context
			nextContextRegisterValue =
				combineRegisterValues(repeatedNoflowValue, nextContextRegisterValue, true);
		}

		// combine default context
		RegisterValue defaultValue = programContext.getDefaultValue(contextRegister, address);
		nextContextRegisterValue =
			combineRegisterValues(defaultValue, nextContextRegisterValue, true);

		if (nextContextRegisterValue == null) {
			nextContextRegisterValue = new RegisterValue(contextRegister);
		}

		return nextContextRegisterValue;
	}

	private void setNextContextChangePoint(Address currentAddress) {
		AddressRange range =
			programContext.getRegisterValueRangeContaining(contextRegister, currentAddress);
		contextChangePoint = null;
		try {
			contextChangePoint = range.getMaxAddress().addNoWrap(1);
		}
		catch (AddressOverflowException e) {
			// end of space
		}
	}

	/**
	 * Ends the current flow.  Unsaved register values will be saved up to and including max address.
	 * @param maxAddress the maximum address of an instruction flow.  If maxAddress is null,
	 * or the current flow address has already advanced beyond maxAddress, then no save is performed.
	 * @throws IllegalStateException if a flow has not been started.
	 */
	public void flowEnd(Address maxAddress) {
		if (!isFlowActive()) {
			throw new IllegalStateException("Attempted to end a flow that was not started.");
		}
		if (maxAddress != null && maxAddress.compareTo(startAddr) >= 0) {
			saveProgramContext(startAddr, maxAddress);
		}
		startAddr = null;
		currentAddress = null;
	}

	@Override
	public List<Register> getRegisters() {
		return programContext.getRegisters();
	}

	@Override
	public Register getRegister(String name) {
		return programContext.getRegister(name);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		if (register == null) {
			return null;
		}
		if (register.isProcessorContext()) {
			RegisterValue registerValue = null;
			if (contextRegister != null) {
				registerValue = contextRegisterValue.getRegisterValue(register);
			}
			return registerValue;
		}

		Register baseRegister = register.getBaseRegister();

		// if we have a current value and it specifies all the required bits then return it
		RegisterValue value = registerStateMap.get(baseRegister);
		if (value != null) {
			value = value.getRegisterValue(register);
		}
		if (value != null && value.hasValue()) {
			return value;
		}

		// otherwise get the value stored in the program and combine with any current bits
		RegisterValue programValue = programContext.getRegisterValue(baseRegister, currentAddress);
		if (programValue == null) {
			return value;
		}
		programValue = programValue.getRegisterValue(register);

		return programValue.combineValues(value);
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		RegisterValue value = getRegisterValue(register);
		if (value != null) {
			return signed ? value.getSignedValue() : value.getUnsignedValue();
		}
		return null;
	}

	/**
	 * Sets the value for the given register to be used when the flow advances to the given address
	 * using either the flowTo() or flowStart() methods.  The new value has precedence over any
	 * existing value.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param register the register for which the value is to be saved.
	 * @param address the future flow address to save the value.
	 * @param newValue the value to save for future flow.
	 */
	public void setValue(Register register, Address address, BigInteger newValue) {
		setRegisterValue(Address.NO_ADDRESS, address, new RegisterValue(register, newValue), true);
	}
	
	/**
	 * Sets the value for the given register to be used when the flow advances to the given address
	 * using either the flowTo() or flowStart() methods.  The new value has precedence over any
	 * existing value.
	 * 
	 * @param register the register for which the value is to be saved.
	 * @param fromAddr the address from which this flow originated
	 * @param toAddr the future flow address to save the value.
	 * @param newValue the value to save for future flow.
	 */
	public void setValue(Register register, Address fromAddr, Address toAddr, BigInteger newValue) {
		setRegisterValue(fromAddr, toAddr, new RegisterValue(register, newValue), true);
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		setFutureRegisterValue(Address.NO_ADDRESS, address, value);
	}
	
	@Override
	public void setFutureRegisterValue(Address fromAddr, Address toAddr, RegisterValue value) {
		setRegisterValue(fromAddr, toAddr, value, true);
	}

	/**
	 * Stores register value in map.
	 * If <code>newValuePrecedence</code> is true, then the given <code>newValue</code>
	 * overrides the <code>currentValue</code>.
	 * 
	 * @param fromAddr the address from which the Register value flows.
	 * @param destAddr the address to store the new value
	 * @param newValue new value to store
	 * @param newValuePrecedence true if the new value has precedence over any old value
	 */
	private void setRegisterValue(Address fromAddr, Address destAddr,
			RegisterValue newValue, boolean newValuePrecedence) {
		if (newValue == null) {
			return;
		}
		if (isFlowActive() && currentAddress.equals(destAddr)) {
			setRegisterValue(newValue);
			return;
		}
		Register register = newValue.getRegister();
		Register baseRegister = register.getBaseRegister();

		// get the future flow state map for the given address
		Map<Register, RegisterValue> stateMap = findFutureFlowStateMap(fromAddr, destAddr);

		// merge the new value with any existing future value or a value from the program if the future
		// value was not previously set.
		RegisterValue value = stateMap.get(baseRegister);
		if (value == null) {
			// if there is no previously saved future value, always give precedence to the new value.
			value = programContext.getNonDefaultValue(baseRegister, destAddr);
			newValuePrecedence = true;
		}
		value = combineRegisterValues(value, newValue, newValuePrecedence);

		stateMap.put(baseRegister, value);
	}

	/**
	 * Combines two Register values.  
	 * @param currentValue the current value
	 * @param newValue the new value
	 * @param newValuePrecedence if true, new value has precedence for active bits, else currentValue
	 * has precedence for active bits.
	 * @return the combined register value or null if both values are null
	 */
	private RegisterValue combineRegisterValues(RegisterValue currentValue, RegisterValue newValue,
			boolean newValuePrecedence) {
		if (currentValue == null || !currentValue.hasAnyValue()) {
			return newValue;
		}
		if (newValue == null || !newValue.hasAnyValue()) {
			return currentValue;
		}
		if (newValuePrecedence) {
			return currentValue.combineValues(newValue);
		}
		return newValue.combineValues(currentValue);
	}

	/**
	 * Returns the current flow address for this context.
	 */
	public Address getAddress() {
		return currentAddress;
	}

	/**
	 * Saves the context from the startAddr (inclusive) to the end address (inclusive)
	 * back to the program's stored context.
	 * @param startAddress 
	 * @param endAddress 
	 */
	private void saveProgramContext(Address start, Address end) {
		if (end == null || start.compareTo(end) > 0) {
			throw new IllegalArgumentException("Invalid context range: (" + start + "," + end + ")");
		}

// TODO: Should disassembler context be used for anything other than the context-register ??

		Iterator<Register> it = registerStateMap.keySet().iterator();
		while (it.hasNext()) {
			Register reg = it.next();
			if (reg.isProcessorContext()) {
				continue;
			}
			RegisterValue value = registerStateMap.get(reg);
			try {
				programContext.setRegisterValue(start, end, value);
			}
			catch (ContextChangeException e) {
				// we should never be writing the context register
			}
		}
	}

	@Override
	public boolean hasValue(Register register) {
		BigInteger value = getValue(register, true);
		return value != null;
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		setRegisterValue(new RegisterValue(register, value));
	}

	@Override
	public void clearRegister(Register register) {
		if (!isFlowActive()) {
			throw new IllegalStateException("Context flow has not be started");
		}
		if (!startAddr.equals(currentAddress)) {
			saveProgramContext(startAddr, currentAddress.previous());
			startAddr = currentAddress;
		}
		if (register.isProcessorContext()) {
			if (contextRegisterValue != null) {
				contextRegisterValue = contextRegisterValue.clearBitValues(register.getBaseMask());
			}
		}
		else {
			Register baseRegister = register.getBaseRegister();
			RegisterValue currentValue = registerStateMap.remove(baseRegister);
			if (currentValue != null && !register.isBaseRegister()) {
				currentValue = currentValue.clearBitValues(register.getBaseMask());
				if (currentValue.hasAnyValue()) {
					registerStateMap.put(baseRegister, currentValue);
				}
			}
		}
	}

	/**
	 * Modify the current context register value at the specified address.  If current 
	 * disassembly flow address equals specified address the current disassembly context 
	 * will be changed, otherwise the future flow state will be changed. This differs from 
	 * {@link #setValue(Register, Address, BigInteger)} in that is can affect the current 
	 * context state at the current address in a non-delayed fashion.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param value register value
	 * @param address disassembly address
	 */
	public void setContextRegisterValue(RegisterValue value, Address address) {
		setContextRegisterValue(value, Address.NO_ADDRESS, address);
	}
	
	/**
	 * Modify the current context register value at the specified address.  If current 
	 * disassembly toAddr address equals specified address the current disassembly context 
	 * will be changed, otherwise the future flow state flowing from the fromAddr will be changed.
	 * This differs from {@link #setValue(Register, Address, BigInteger)} in that is can
	 * affect the current context state at the current address in a non-delayed fashion.
	 * 
	 * @param value register value
	 * @param fromAddr the address from which this flow originated
	 * @param toAddr the future flow address to save the value.
	 */
	public void setContextRegisterValue(RegisterValue value, Address fromAddr, Address toAddr) {
		if (value == null) {
			return;
		}
		Register baseReg = value.getRegister().getBaseRegister();
		if (!baseReg.isProcessorContext() || baseReg != contextRegister) {
			throw new IllegalArgumentException("Invalid processor context register value");
		}
		if (isFlowActive() && currentAddress.equals(toAddr)) {
			contextRegisterValue = contextRegisterValue.combineValues(value);
			return;
		}
		setRegisterValue(fromAddr, toAddr, value, true);
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		if (value == null) {
			return;
		}
		if (!isFlowActive()) {
			throw new IllegalStateException("Context flow has not been started");
		}

		Register register = value.getRegister();
		if (register.isProcessorContext()) {
			// flow is already active - assume delayed flow context
			if (delayedContextRegisterValue == null) {
				delayedContextRegisterValue = contextRegisterValue;
			}
			delayedContextRegisterValue =
				combineRegisterValues(delayedContextRegisterValue, value, true);
			return; // delay saving of range context
		}

		if (!startAddr.equals(currentAddress)) {
			saveProgramContext(startAddr, currentAddress.previous());
			startAddr = currentAddress;
		}

		Register baseRegister = register.getBaseRegister();
		RegisterValue currentValue = registerStateMap.remove(baseRegister);
		RegisterValue newValue = combineRegisterValues(currentValue, value, true);
		registerStateMap.put(baseRegister, newValue);
	}

	/**
	 * Returns the future register value at the specified address.  If no future value is stored,
	 * it will return the value stored in the program.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param register the register to get a value for.
	 * @param address the address at which to get a value.
	 * @param signed if true, interpret the value as signed.
	 * @return the value of the register at the location, or null if a full value is not established.
	 */
	public BigInteger getValue(Register register, Address address, boolean signed) {
		return getValue(register, Address.NO_ADDRESS, address, signed);
	}
	
	/**
	 * Returns the future register value at the specified address that occurred because of a flow
	 * from the fromAddr.  If no future value is stored, it will return the value stored in the program.
	 *
	 * @param register the register to get a value for.
	 * @param fromAddr the address from which this flow originated.
	 * @param toAddr the future flow address to save the value.
	 * @param signed if true, interpret the value as signed.
	 * @return the value of the register at the location, or null if a full value is not established.
	 */
	public BigInteger getValue(Register register, Address fromAddr, Address toAddr, boolean signed) {
		RegisterValue value = getRegisterValue(register, fromAddr, toAddr);
		if (value == null) {
			return null;
		}
		return signed ? value.getSignedValue() : value.getUnsignedValue();
	}

	/**
	 * Returns the future RegisterValue at the specified address.  If no future value is stored,
	 * it will return the value stored in the program. The value returned may not have a complete
	 * value for the requested register.
	 * 
	 * Use this method if keeping separate flows from different flow from addresses is not important.
	 * 
	 * @param register the register to get a value for.
	 * @param address the address at which to get a value.
	 * @return a RegisterValue object if one has been stored in the future flow or the program.
	 * The RegisterValue object may have a "no value" state for the bits specified by the given register.
	 * Also, null may be returned if no value have been stored.
	 */
	public RegisterValue getRegisterValue(Register register, Address address) {
		return getRegisterValue(register, Address.NO_ADDRESS, address);
	}
	
	/**
	 * Returns the future RegisterValue at the specified address that occurred because of a flow from
	 * the fromAddr.  If no future value is stored, it will return the value stored in the program.
	 * The value returned may not have a complete value for the requested register.
	 * 
	 * @param register the register to get a value for.
	 * @param fromAddr the address from which the flow originated
	 * @param destAddr the address at which to get a value.
	 * 
	 * @return a RegisterValue object if one has been stored in the future flow or the program.
	 * The RegisterValue object may have a "no value" state for the bits specified by the given register.
	 * Also, null may be returned if no value have been stored.
	 */
	public RegisterValue getRegisterValue(Register register, Address fromAddr, Address destAddr) {
		if (isFlowActive() && destAddr.compareTo(startAddr) >= 0 &&
				destAddr.compareTo(currentAddress) <= 0) {
			return getRegisterValue(register);
		}
		
		Map<Address, Map<Register, RegisterValue>> futureRegisterStateMap = noAddressFutureRegisterStateMap;
		if (destAddr != Address.NO_ADDRESS) {
			futureRegisterStateMap = futureFlowRegisterStateMaps.get(destAddr);
		}
		Map<Register, RegisterValue> map = null;
		if (futureRegisterStateMap != null) {
			map = futureRegisterStateMap.get(fromAddr);
		}
		
		if (map != null) {
			RegisterValue value = map.get(register.getBaseRegister());
			if (value != null) {
				return value.getRegisterValue(register);
			}
		}
		return programContext.getRegisterValue(register, destAddr);
	}
	
	/**
	 * Returns an array of locations that have values that will flow to this location
	 * 
	 * @param toAddr address that is the target of a flow to
	 * @return and array of known address flows to this location
	 */
	public Address[] getKnownFlowToAddresses(Address toAddr) {		

		// does this have a NO_ADRESS from flow to the toAddr?
		Map<Register, RegisterValue> map = noAddressFutureRegisterStateMap.get(toAddr);
		boolean has_NO_ADDRESS_flow = map != null;
		
		int extraForNoAddr = (has_NO_ADDRESS_flow ? 1 : 0);
		Address[] flowsTo = new Address[0+extraForNoAddr];
		
		if (toAddr != null && toAddr != Address.NO_ADDRESS) {
			Map<Address, Map<Register, RegisterValue>> futureRegisterStateMap = futureFlowRegisterStateMaps.get(toAddr);
			
			if (futureRegisterStateMap != null) {
				Set<Address> keySet = futureRegisterStateMap.keySet();
				flowsTo = keySet.toArray(new Address[keySet.size() + extraForNoAddr]);
			}
		}
		
		if (has_NO_ADDRESS_flow) {
			flowsTo[flowsTo.length-1] = Address.NO_ADDRESS;
		}
		
		return flowsTo;
	}

	/**
	 * Returns true if a flow has been started and not yet ended.
	 * @return true if a flow has been started and not yet ended.
	 */
	public boolean isFlowActive() {
		return startAddr != null;
	}
}
