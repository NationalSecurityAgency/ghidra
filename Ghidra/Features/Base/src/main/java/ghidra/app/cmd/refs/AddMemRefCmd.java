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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Command class to add a memory reference to the program.
 */
public class AddMemRefCmd implements Command {

	private Address fromAddr;
	private Address toAddr;
	private RefType refType;
	private SourceType source;
	private int opIndex;
	private boolean setPrimary;

	/**
     * Command constructor for adding a memory reference with a default refType
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr address of the location being referenced.
	 * @param source the source of the reference
	 * @param opIndex the operand index in the code unit where the reference occurs
	 * @param setPrimary true if this reference should be primary. 
     */
    public AddMemRefCmd(Address fromAddr, Address toAddr,
    		SourceType source, int opIndex, boolean setPrimary) {
    	this(fromAddr, toAddr, null, source, opIndex, setPrimary);
    }
    
    /**
     * Command constructor for adding a memory reference
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr address of the location being referenced.
	 * @param refType reference type - how the location is being referenced.
	 * @param source the source of the reference
	 * @param opIndex the operand index in the code unit where the reference occurs 
     */
    public AddMemRefCmd(Address fromAddr, Address toAddr, RefType refType, 
			SourceType source, int opIndex) {
    	this(fromAddr, toAddr, refType, source, opIndex, false);
    }

    /**
     * Command constructor for adding a memory reference
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr address of the location being referenced.
	 * @param refType reference type - how the location is being referenced.
	 * @param source the source of the reference
	 * @param opIndex the operand index in the code unit where the reference occurs
	 * @param setPrimary set the newly added reference primary 
     */
    public AddMemRefCmd(Address fromAddr, Address toAddr,  RefType refType, 
			SourceType source, int opIndex, boolean setPrimary) {
    	this.fromAddr    = fromAddr;
    	this.toAddr      = toAddr;
    	this.refType     = refType;
    	this.source      = source;
    	this.opIndex     = opIndex;
    	this.setPrimary  = setPrimary;
    }
    
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
    public boolean applyTo(DomainObject obj) {
    	Program p = (Program)obj;
    	
    	if (refType == null) {
    		CodeUnit cu = p.getListing().getCodeUnitAt(fromAddr);
    		if (cu != null) {
    			refType = RefTypeFactory.getDefaultMemoryRefType(cu, opIndex, toAddr, false);
    		}
    	}
    	
    	ReferenceManager refMgr = p.getReferenceManager();
		Reference ref = refMgr.addMemoryReference(fromAddr, toAddr, refType, source, opIndex);
		if (setPrimary) {
			refMgr.setPrimary(ref, setPrimary);
		}
		return true;
    }
 

    /**
     * @see ghidra.framework.cmd.Command#getStatusMsg()
     */
    public String getStatusMsg() {
        return "";
    }

    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName() {
        return "Add Memory Reference";
    }

}
