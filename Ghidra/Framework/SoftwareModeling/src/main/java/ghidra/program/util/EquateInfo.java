/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.util;

import ghidra.program.model.address.Address;

/**
 * Class to hold information about an Equate; it is used
 * in a ProgramChangeRecord when an equate is created and
 * when references to the Equate are updated.
 */
public class EquateInfo {

    private String name;
    private long value;
    private Address refAddr;
    private int opIndex;
    private long dynamicHash;

    /**
     * Constructor.
     * 
     * @param name   Equate name
     * @param value  Equate value
     * @param refAddr Reference address (may be null for some event types)
     * @param opIndex operand index for the reference; useful only if 
     * refAddr is not null. May be -1 if only dynamicHash applies.
     * @param dynamicHash dynamic hash. May be 0 if only opIndex applies.
     */
    public EquateInfo(String name, long value, Address refAddr, int opIndex, long dynamicHash) {
        this.name = name;
        this.value = value;
        this.refAddr = refAddr;
        this.opIndex = opIndex;
    }

    /**
     * Get the equate name.
     */
    public String getName() {
        return name;
    }

    /**
     * Get the equate value.
     */
    public long getValue() {
        return value;
    }

    /**
     * Get the reference address.
     */
    public Address getReferenceAddress() {
        return refAddr;
    }

    /**
     * Get the operand index of where the equate was placed;
     * This value is meaningful only if the reference address is not null, and
     * may be -1 if only the dynamicHash applies.
     */
    public int getOperandIndex() {
        return opIndex;
    }
    
    /**
     * Get the varnode dynamic hash of where the equate was placed;
     * This value is meaningful only if the reference address is not null, and
     * may be 0 if only the operand index applies.
     */
    public long getDynamicHash() {
    	return dynamicHash;
    }

    /**
     * Return a meaningful string for debugging purposes.
     */
    @Override
    public String toString() {
        return "Name=" + name +
            ",value=" + value +
            ", RefAddr=" + refAddr +
            ", opIndex="+ opIndex +
            ", dynamicHash=0x" + Long.toHexString(dynamicHash);
    }
}
