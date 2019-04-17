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
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *  CodeBlockReferenceImpl implements a CodeBlockReference.
 * <P>
 *  A <CODE>CodeBlockReference</CODE> represents the flow from one source block
 * to a destination block, including information about how
 * flow occurs between the two blocks (JUMP, CALL, etc..).
 * <P>
 *  The <CODE>reference</CODE> is the address in the destination
 * block that is actually flowed to by some instruction in the source block.
 * <P>
 *  The <CODE>referent</CODE> is the address of the instruction in
 * the source block that flows to the destination block.
 * <P>
 * 
 * @see ghidra.program.model.block.CodeBlockReference
 */
public class CodeBlockReferenceImpl implements CodeBlockReference {

	private CodeBlock source;          // source block for this flow. 
	private CodeBlock destination;     // destination block for this flow.

	private FlowType flowType;         // how we flow to the block

	// The actual address in the destination block referenced
	// by the instruction in the source block
	private Address reference;

	// The address of the instruction in the source block
	// that causes flows to the destination block.
	private Address referent;

	/**
	 * Constructor for a CodeBlockReferenceImpl
	 * @param source source block for this flow
	 * @param destination destination block for this flow
	 * @param flowType how we flow
	 * @param reference reference address in destination block
	 * @param referent address of instruction in source block that flows to destination block.
	 */
	public CodeBlockReferenceImpl(CodeBlock source, CodeBlock destination, FlowType flowType,
			Address reference, Address referent) {
		this.source = source;
		this.destination = destination;
		this.reference = reference;
		this.referent = referent;
		this.flowType = flowType;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getSourceBlock()
	 */
	@Override
	public CodeBlock getSourceBlock() {
		return getBlock(source, destination, referent);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getDestinationBlock()
	 */
	@Override
	public CodeBlock getDestinationBlock() {
		return getBlock(destination, source, reference);
	}

	/**
	 * Gets the block (source or destination).  If the block is needed,
	 * assume we have the blockHave and compute blockNeeded using that block.
	 * 
	 * @param blockNeeded - block we need 
	 * @param blockHave - block we know
	 * @param addrInBlock - address in the block we need
	 * @return the block
	 */
	private CodeBlock getBlock(CodeBlock blockNeeded, CodeBlock blockHave, Address addrInBlock) {
		if (blockNeeded == null) {
			CodeBlockModel model = blockHave.getModel();
			try {
				blockNeeded =
					model.getFirstCodeBlockContaining(addrInBlock, TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (CancelledException e) {
				// can't happen, dummy monitor can't be canceled
			}

			// means that there wasn't a good source block there,
			//    make an invalid source block
			//  TODO: This might not be the right thing to do.  Return a
			//        codeBlock that really isn't there, but should be if
			//        there were valid instructions.  If you got it's start
			//        address then got the block starting at from the model,
			//        you would get null, so maybe the model should be changed
			//        to return a block at this address....
			if (blockNeeded == null) {
				if (model instanceof SimpleBlockModel) {
					blockNeeded =
						((SimpleBlockModel) model).createSimpleDataBlock(addrInBlock, addrInBlock);
				}
			}
		}
		return blockNeeded;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getFlowType()
	 */
	@Override
	public FlowType getFlowType() {
		return flowType;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getReference()
	 */
	@Override
	public Address getReference() {
		return reference;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getReferent()
	 */
	@Override
	public Address getReferent() {
		return referent;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getSourceAddress()
	 */
	@Override
	public Address getSourceAddress() {
		CodeBlock block = getSourceBlock();
		if (block != null) {
			return block.getFirstStartAddress();
		}
		return referent;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockReference#getDestinationAddress()
	 */
	@Override
	public Address getDestinationAddress() {
		CodeBlock block = getDestinationBlock();
		if (block != null) {
			return block.getFirstStartAddress();
		}
		return reference;
	}

	@Override
	public String toString() {
		return referent + " -> " + reference;
	}
}
