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
package ghidra.program.util;

import ghidra.framework.model.DomainObjectChangeRecord;

public class UserDataChangeRecord extends DomainObjectChangeRecord {

    private final static long serialVersionUID = 1;
    private Object oldValue;
    private Object newValue;
    private String propertyName;
	
    /**
     * Constructor
     * @param propertyName name of the property
     * @param oldValue old value
     * @param newValue new value
     */
    public UserDataChangeRecord(String propertyName,
                                        Object oldValue,
                                        Object newValue) { 
        super(ChangeManager.DOCR_USER_DATA_CHANGED);
        this.propertyName = propertyName;
        this.oldValue = oldValue;
        this.newValue = newValue;
    }
    
	/**
	 * Constructor for change record for removing a range of properties.
	 * @param propertyName name of the property
	 */
	public UserDataChangeRecord(String propertyName) {
		super(ChangeManager.DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED);
		this.propertyName = propertyName;
	}
		
    /**
     * Get the name of the property being changed.
     */
    public String getPropertyName() {
        return propertyName;
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
    
}
