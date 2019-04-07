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

import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.program.model.address.Address;

/**
 * Change record generated when a property on a code unit changes.
 */
public class CodeUnitPropertyChangeRecord extends DomainObjectChangeRecord {

    private final static long serialVersionUID = 1;
    private Object oldValue;
    private Object newValue;
    private String propertyName;
    private Address addr;
	private Address startAddr;
	private Address endAddr;
	
    /**
     * Constructor
     * @param propertyName name of the property
     * @param codeUnitAddr address of the code unit
     * @param oldValue old value
     * @param newValue new value
     */
    public CodeUnitPropertyChangeRecord(String propertyName,
                                        Address codeUnitAddr,
                                        Object oldValue,
                                        Object newValue) { 
        super(ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED);
        this.propertyName = propertyName;
        addr = codeUnitAddr;
        this.oldValue = oldValue;
        this.newValue = newValue;
    }
	/**
	 * Constructor for change record for removing a range of properties.
	 * @param propertyName name of the property
	 * @param start start of the range of properties being removed
	 * @param end end of the range of properties being removed
	 */
	public CodeUnitPropertyChangeRecord(String propertyName,
		Address start, Address end) {
		super(ChangeManager.DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED);
		this.propertyName = propertyName;
		startAddr = start;
		endAddr = end;
	}
		
    /**
     * Get the name of the property being changed.
     */
    public String getPropertyName() {
        return propertyName;
    }

    /**
     * Get the address of the code unit for this property change.
     */
    public Address getAddress() {
        return addr;
    }

    /**
     * Get the original value.
     */
    @Override
    public Object getOldValue() {
        return oldValue;
    }

    /**
     * Get the new value.
     */
    @Override
    public Object getNewValue() {
        return newValue;
    }
    
    /**
     * Get the start address of the range of properties that were removed.
     * @return null if the event type is not 
     * ChangeManager.DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED
     */
    public Address getStartAddress() {
    	return startAddr;
    }
    /**
     * Get the end address of the range of properties that were removed.
     * @return null if the event type is not 
     * ChangeManager.DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED
     */
    public Address getEndAddress() {
    	return endAddr;
    }
}
