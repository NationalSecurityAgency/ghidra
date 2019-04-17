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

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>AddMemRefsCmd</code> adds a set of memory references from a
 * specified address and opIndex to all code units identified by a 
 * set of addresses.
 */
public class AddMemRefsCmd extends BackgroundCommand {

	private Address fromAddr;
	private AddressSetView toSet;
	private RefType refType;
	private SourceType source;
	private int opIndex;

	/**
	 * Add memory references.
	 * @param fromAddr reference source
	 * @param toSet set of addresses which make up reference destinations.
	 * Only those addresses on code where a code unit exists will be considered.
	 * @param refType reference type to be applied.
	 * @param source the source of the reference
	 * @param opIndex source operand index
	 */
	public AddMemRefsCmd(Address fromAddr, AddressSetView toSet, RefType refType,
			SourceType source, int opIndex) {
		super("Add Memory References", true, true, false);

		this.fromAddr = fromAddr;
		this.toSet = toSet;
		this.refType = refType;
		this.source = source;
		this.opIndex = opIndex;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		Program p = (Program) obj;
		ReferenceManager refMgr = p.getReferenceManager();
		Listing listing = p.getListing();

		monitor.initialize(toSet.getNumAddresses());
		monitor.setMessage("Adding memory references...");

		int cnt = 0;
		AddressIterator iter = toSet.getAddresses(true);
		CodeUnit prevCodeUnit = null;
		while (!monitor.isCancelled() && iter.hasNext()) {
			Address toAddr = iter.next();
			if (prevCodeUnit == null || !prevCodeUnit.contains(toAddr)) {
				CodeUnit cu = getSmallestCodeUnitAt(listing, toAddr);
				if (cu != null) {
					prevCodeUnit = cu;
					refMgr.addMemoryReference(fromAddr, toAddr, refType, source, opIndex);
				}
			}
			monitor.setProgress(++cnt);
		}
		return true;
	}

	private CodeUnit getSmallestCodeUnitAt(Listing listing, Address addr) {
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if ((data.getNumComponents() == 0) || (data.isUnion()) || (data.isArray())) {
				return data;
			}
			long diff = addr.subtract(data.getMinAddress());
			return data.getPrimitiveAt((int) (diff));
		}
		return cu;
	}
}
