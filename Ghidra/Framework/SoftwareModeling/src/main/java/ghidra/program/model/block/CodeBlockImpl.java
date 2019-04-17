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
package ghidra.program.model.block;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * CodeBlockImpl is an implementation of a CodeBlock.
 * These are produced by a particular CodeBlockModel and are associated
 * with only that model.  Most methods simply delegate any work that
 * is specific to a particular CodeBlockModel to that model.
 *
 * @see ghidra.program.model.block.CodeBlock
 */
public class CodeBlockImpl implements CodeBlock {

	private CodeBlockModel model; // model that produced this block
	private Address starts[]; // entry points into block.  Addresses are stored
	// in natural sorted order.
	private AddressSetView set; // set of addresses that make up this block

	/**
	 * Construct a multi-entry CodeBlock associated with a CodeBlockModel. The
	 * significance of the start Addresses is model dependent.
	 * @param model the model instance which produced this block.
	 * @param starts the entry points for the block. Any of these addresses may
	 * be used to identify this block within the model that produced it.
	 * @param body the address set which makes-up the body of this block.
	 */
	public CodeBlockImpl(CodeBlockModel model, Address starts[], AddressSetView body) {
		if (starts != null) {
			this.starts = starts.clone();
			Arrays.sort(this.starts); // store start Addresses in natural sorted order
		}
		this.model = model;
		this.set = body;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getFirstStartAddress()
	 */
	@Override
	public Address getFirstStartAddress() {
		return starts[0];
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getStartAddresses()
	 */
	@Override
	public Address[] getStartAddresses() {
		return starts;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getName()
	 */
	@Override
	public String getName() {
		return model.getName(this);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getFlowType()
	 */
	@Override
	public FlowType getFlowType() {
		return model.getFlowType(this);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getNumSources(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public int getNumSources(TaskMonitor monitor) throws CancelledException {
		return model.getNumSources(this, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getSources(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlockReferenceIterator getSources(TaskMonitor monitor) throws CancelledException {
		return model.getSources(this, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getNumDestinations(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public int getNumDestinations(TaskMonitor monitor) throws CancelledException {
		return model.getNumDestinations(this, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getDestinations(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlockReferenceIterator getDestinations(TaskMonitor monitor)
			throws CancelledException {
		return model.getDestinations(this, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlock#getModel()
	 */
	@Override
	public CodeBlockModel getModel() {
		return model;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		List<Address> sList = new ArrayList<Address>();
		List<Address> dList = new ArrayList<Address>();

		try {
			CodeBlockReferenceIterator ri = getSources(TaskMonitorAdapter.DUMMY_MONITOR);
			while (ri.hasNext()) {
				CodeBlockReference ref = ri.next();
				Address a = ref.getSourceAddress();
				sList.add(a);
			}
			CodeBlockReferenceIterator di = getDestinations(TaskMonitorAdapter.DUMMY_MONITOR);
			while (di.hasNext()) {
				CodeBlockReference ref = di.next();
				Address a = ref.getDestinationAddress();
				dList.add(a);
			}
		}
		catch (CancelledException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return model.getName(this) + "  src:" + sList + "  dst:" + dList;
	}

	//
	// implementation of AddressSetView
	//

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address a) {
		return set.contains(a);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address start, Address end) {
		return set.contains(start, end);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean contains(AddressSetView rangeSet) {
		return set.contains(rangeSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersects(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean intersects(Address start, Address end) {
		return set.intersects(start, end);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersects(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean intersects(AddressSetView addrSet) {
		return set.intersects(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersect(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet intersect(AddressSetView view) {
		return set.intersect(view);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersectRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return set.intersectRange(start, end);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#union(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet union(AddressSetView addrSet) {
		return set.union(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#xor(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return set.xor(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#subtract(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return set.subtract(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return set.isEmpty();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getMinAddress()
	 */
	@Override
	public Address getMinAddress() {
		return set.getMinAddress();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getMaxAddress()
	 */
	@Override
	public Address getMaxAddress() {
		return set.getMaxAddress();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getNumAddressRanges()
	 */
	@Override
	public int getNumAddressRanges() {
		return set.getNumAddressRanges();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddressRanges()
	 */
	@Override
	public AddressRangeIterator getAddressRanges() {
		return set.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return set.getAddressRanges();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getNumAddresses()
	 */
	@Override
	public long getNumAddresses() {
		return set.getNumAddresses();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(boolean)
	 */
	@Override
	public AddressIterator getAddresses(boolean forward) {
		return set.getAddresses(forward);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return set.getAddresses(start, forward);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#hasSameAddresses(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return set.hasSameAddresses(view);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		CodeBlockImpl block = (CodeBlockImpl) obj;

		if (!model.getName().equals(block.model.getName())) {
			return false;
		}
		if (block.starts.length != starts.length) {
			return false;
		}
		for (int i = 0; i < starts.length; i++) {
			if (!starts[i].equals(block.starts[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddressRanges(boolean)
	 */
	@Override
	public AddressRangeIterator getAddressRanges(boolean startAtFront) {
		return set.getAddressRanges(startAtFront);
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return starts[0].hashCode();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return set.getAddressRanges(start, forward);
	}

	@Override
	public AddressRange getFirstRange() {
		return set.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return set.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return set.getRangeContaining(address);
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return set.iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return set.iterator(start, forward);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView otherSet) {
		return set.findFirstAddressInCommon(otherSet);
	}

}
