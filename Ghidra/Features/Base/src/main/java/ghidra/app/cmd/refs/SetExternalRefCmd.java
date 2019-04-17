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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command class for adding external references.
 */
public class SetExternalRefCmd implements Command {

	private Address fromAddr;
	private int opIndex;
	private String extName;
	private String extLabel;
	private Address extAddr;
	private String errMsg;
	private RefType refType;
	private SourceType source;

	/**
	 * Constructs a new command for adding external references.
	 * @param fromAddr from address (source of the reference)
	 * @param opIndex operand index
	 * @param extName name of external program
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr address within the external program, may be null
	 * @param refType reference type (NOTE: data/pointer should generally utilize {@link RefType#DATA}
	 * @param source the source of this reference
	 */
	public SetExternalRefCmd(Address fromAddr, int opIndex, String extName, String extLabel,
			Address extAddr, RefType refType, SourceType source) {
		this.fromAddr = fromAddr;
		this.opIndex = opIndex;
		this.extName = extName;
		this.extLabel = extLabel;
		this.extAddr = extAddr;
		this.refType = refType;
		this.source = source;
	}
	
	/**
	 * Constructs a new command for adding an external reference from data using {@link RefType#DATA}.
	 * @param fromAddr from address (source of the reference)
	 * @param opIndex operand index
	 * @param extName name of external program
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr address within the external program, may be null
	 * @param source the source of this reference
	 * @deprecated the other constructor form should be used with an appropriate RefType specified.
	 * {@link RefType#DATA} should be used for address table pointer references.
	 */
	@Deprecated
	public SetExternalRefCmd(Address fromAddr, int opIndex, String extName, String extLabel,
			Address extAddr, SourceType source) {
		this(fromAddr, opIndex, extName, extLabel, extAddr, RefType.DATA, source);
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		ReferenceManager refMgr = ((Program) obj).getReferenceManager();

		// Remove existing references
//		Reference[] refs = refMgr.getReferencesFrom(fromAddr, opIndex);
//		for (int i = 0; i < refs.length; i++) {
//			refMgr.delete(refs[i]);
//		}

		try {
			refMgr.addExternalReference(fromAddr, extName, extLabel, extAddr, source, opIndex,
				refType);
			return true;
		}
		catch (DuplicateNameException e) {
			errMsg = e.getMessage();
		}
		catch (InvalidInputException e) {
			errMsg = e.getMessage();
		}
		return false;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errMsg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Set External Reference";
	}

}
