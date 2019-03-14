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
/*
 * Created on May 24, 2006
 */
package ghidra.app.plugin.core.datapreview;

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

class DataTypeComponentPreview implements Preview {
    private DataTypeComponentPreview parentPreview;
    private Composite composite;
    private DataTypeComponent dtc;

    DataTypeComponentPreview(Composite composite, DataTypeComponent dtc) {
        this.composite = composite;
        this.dtc = dtc;
    }

    DataTypeComponentPreview getParent() {
        return parentPreview;
    }

    DataTypeComponentPreview getRoot() {
        DataTypeComponentPreview parent = parentPreview;
        if (parent == null) {
            return null;
        }
        while (parent.getParent() != null) {
            parent = parent.getParent();
        }
        return parent;
    }

    void setParent(DataTypeComponentPreview parent) {
        this.parentPreview = parent;
    }

    public String getName() {
        String fieldName = dtc.getFieldName();
        if (fieldName == null) {
            fieldName = dtc.getDefaultFieldName();
        }
        if (parentPreview == null) {
            return composite.getName()+"."+fieldName;
        }
        return parentPreview.getName()+"."+fieldName;
    }

    public String getPreview(Memory memory, Address addr) {
	    try {
	        if (parentPreview != null) {
	            addr = addr.add(parentPreview.dtc.getOffset());
	        }
	        addr = addr.add(dtc.getOffset());
		    MemBuffer mb = new DumbMemBufferImpl(memory, addr);
		    DataType dt = dtc.getDataType();
		    return dt.getRepresentation(mb, new SettingsImpl(), dtc.getLength());
	    }
	    catch (Exception e) {
	        return "ERROR: unable to create preview";
	    }
    }

	public DataType getDataType() {
	    if (parentPreview != null) {
	        return parentPreview.getDataType();
	    }
	    return composite;
	}

	@Override
    public String toString() {
	    return getName();
	}

    public int compareTo(Preview p) {
        if (p instanceof DataTypeComponentPreview) {
            DataTypeComponentPreview that = (DataTypeComponentPreview)p;

            if (parentPreview != null && that.parentPreview == null) {
                return parentPreview.compareTo(that);
            }
            if (parentPreview == null && that.parentPreview != null) {
                return compareTo(that.parentPreview);
            }
            if (parentPreview != null && that.parentPreview != null) {
                int value = parentPreview.compareTo(that.parentPreview);
                if (value != 0) {
                    return value;
                }
            }
            if (composite.equals(that.composite)) {
                if (dtc.getOffset() < that.dtc.getOffset()) {
                    return -1;
                }
                else if (dtc.getOffset() > that.dtc.getOffset()) {
                    return 1;
                }
                else {
                    return 0;
                }
            }
            return composite.getName().compareTo(that.composite.getName());
        }
        return toString().compareToIgnoreCase(p.toString());
    }
}
