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
package ghidra.program.model.block;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExtCodeBlockImpl extends AddressSet implements CodeBlock {

	// NOTE: This class is not serializable, although it extends AddressSet which is 

	private static EmptyCodeBlockReferenceIterator EMPTY_ITERATOR =
		new EmptyCodeBlockReferenceIterator();

	private CodeBlockModel model;
	private Address extAddr;

	public ExtCodeBlockImpl(CodeBlockModel model, Address extAddr) {
		super(extAddr);
		this.model = model;
		this.extAddr = extAddr;
		if (!extAddr.isExternalAddress()) {
			throw new IllegalArgumentException("Expected external address");
		}
	}

	@Override
	public Address getFirstStartAddress() {
		return extAddr;
	}

	@Override
	public FlowType getFlowType() {
		return RefType.INVALID;
	}

	@Override
	public CodeBlockModel getModel() {
		return model;
	}

	@Override
	public String getName() {
		SymbolTable symTable = model.getProgram().getSymbolTable();
		Symbol s = symTable.getPrimarySymbol(extAddr);
		if (s != null) {
			return s.getName(true);
		}
		return extAddr.toString();
	}

	@Override
	public int getNumDestinations(TaskMonitor monitor) throws CancelledException {
		return 0;
	}

	@Override
	public CodeBlockReferenceIterator getDestinations(TaskMonitor monitor)
			throws CancelledException {
		return EMPTY_ITERATOR;
	}

	@Override
	public int getNumSources(TaskMonitor monitor) throws CancelledException {
		return model.getNumSources(this, monitor);
	}

	@Override
	public CodeBlockReferenceIterator getSources(TaskMonitor monitor) throws CancelledException {
		return model.getSources(this, monitor);
	}

	@Override
	public Address[] getStartAddresses() {
		// TODO Auto-generated method stub
		return new Address[] { extAddr };
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return extAddr.hashCode();
	}

}

class EmptyCodeBlockReferenceIterator implements CodeBlockReferenceIterator {

	@Override
	public boolean hasNext() throws CancelledException {
		return false;
	}

	@Override
	public CodeBlockReference next() throws CancelledException {
		return null;
	}
}
