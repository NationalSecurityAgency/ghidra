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
/*
 * Created on Aug 9, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ghidra.app.plugin.prototype.dataArchiveUtilities;

import ghidra.program.model.data.*;
import ghidra.util.Msg;

import java.util.Hashtable;

public class ComplexName {
	boolean isPointer;
	boolean isArray;
	boolean usesNamespace;
	String complexName;
	String namespace;
	String name;
	int count = 1;
	
	public ComplexName(String complexName) {
		this.complexName = complexName;
		if (complexName.startsWith("Pointer%")) {
			isPointer = true;
			complexName = complexName.substring(complexName.indexOf("%")+1);
		}
		if (complexName.startsWith("Array%")) {
			isArray = true;
			complexName = complexName.substring(complexName.indexOf("%")+1);
			String countStr = complexName.substring(0, complexName.indexOf("%"));
			if (countStr.compareToIgnoreCase("") != 0) {
				count = new Integer(countStr).intValue();
			} else {
				count = 1;
			}
			complexName = complexName.substring(complexName.indexOf("%")+1);
			complexName = complexName.substring(complexName.indexOf("%")+1);
		}
		usesNamespace = (complexName.indexOf(":") >= 0);
		if (usesNamespace) {
			namespace = complexName.substring(complexName.indexOf("/"), complexName.indexOf(":"));
			name      = complexName.substring(0, complexName.indexOf("/"))+
					    complexName.substring(complexName.indexOf(":")+1, complexName.length());
		} else {
			namespace = "";
			name      = complexName;
		}
	}
	public boolean isArray() {
		return isArray;
	}
	public boolean isPointer() {
		return isPointer;
	}
	public String getName() {
		return name;
	}
	public String getNamespace() {
		return namespace;
	}
	public boolean usesNamespace() {
		return usesNamespace;
	}
	public CategoryPath getCategoryPath() {
		return (usesNamespace ? new CategoryPath(namespace) : CategoryPath.ROOT);
	}
	
	public DataType getDataType(FileDataTypeManager dtMgr, Hashtable<String,DataType> dataTypes) {
		return getDataType(dtMgr, dataTypes, true);
	}
	public DataType getDataType(DataTypeManager dtMgr, Hashtable<String,DataType> dataTypes, boolean generateUI) {
		DataType dt;
		if (name.indexOf("%") >= 0) {
			ComplexName cName = new ComplexName(name);
			dt = cName.getDataType(dtMgr, dataTypes, generateUI);
			name = cName.getName();
		} else {
			if (dataTypes == null) {
				dt = dtMgr.getDataType(getCategoryPath(), getName());
			} else {
				dt = dataTypes.get(getCategoryPath()+getName());
			}
			//if (dt == null) {
			//	dt = dtMgr.getDataType(getCategoryPath(), getName());
			//}
		}
		if (dt == null) { 
			if (generateUI) {
				// Add placeholders for the archive entries that are missing
				dt = genUIData(dtMgr, dataTypes, new ComplexName(complexName), 4);
			} else {
			    Msg.warn(this, "Data type ("+name+") not found.");
				return dt;
			}
		}
		if (isPointer) {
			dt = new Pointer32DataType(dt);
		}
		if (isArray) {
			if (dt.getLength() >= 0) {
				dt = new ArrayDataType(dt, count, dt.getLength());
			} else {
			    Msg.error(this, "Error in array length ("+dt.getLength()+") for "+dt.getName());
				return null;
			}
		}
		return dt;
	}
	
	public DataType genUIData(DataTypeManager dtMgr, Hashtable<String,DataType> dataTypes, ComplexName cName, int len) {
		TypedefDataType dt = new TypedefDataType(cName.getCategoryPath(), cName.getName(), 
				new ArrayDataType(new ByteDataType(), len, 1));
    	addDataType(dtMgr, dataTypes, dt);
		return dt;
    }
	
	private void addDataType(DataTypeManager dtMgr, Hashtable<String,DataType> dataTypes, DataType dt) {	
		DataType type = dtMgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		dataTypes.put(type.getCategoryPath()+type.getName(), type);
	}
	
	
}
