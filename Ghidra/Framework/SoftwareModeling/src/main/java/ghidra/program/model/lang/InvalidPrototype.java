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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

import java.util.ArrayList;

/**
 * Class to represent an invalid instruction prototype.
 */
public class InvalidPrototype implements InstructionPrototype, ParserContext {

	private final static Address[] emptyAddresses = new Address[0];

	private Language language;

	/**
	 * Construct a new invalid instruction prototype.
	 */
	public InvalidPrototype(Language lang) {
		super();
		language = lang;
	}

	@Override
	public boolean hasDelaySlots() {
		return false;
	}

	@Override
	public boolean hasCrossBuildDependency() {
		return false;
	}

	@Override
	public Mask getInstructionMask() {
		return null;
	}

	@Override
	public Mask getOperandValueMask(int operandIndex) {
		return null;
	}

	@Override
	public FlowType getFlowType(InstructionContext context) {
		return RefType.INVALID;
	}

	@Override
	public int getDelaySlotDepth(InstructionContext context) {
		return 0;
	}

	@Override
	public boolean isInDelaySlot() {
		return false;
	}

	@Override
	public int getNumOperands() {
		return 1;
	}

	@Override
	public int getOpType(int opIndex, InstructionContext context) {
		return 0;
	}

	@Override
	public Address getFallThrough(InstructionContext context) {
		return null;
	}

	@Override
	public int getFallThroughOffset(InstructionContext context) {
		return 0;
	}

	@Override
	public Address[] getFlows(InstructionContext context) {
		return emptyAddresses;
	}

	public String getOpRepresentation(int opIndex, MemBuffer buf, ProcessorContextView context,
			String label) {
		return "Please Re-Disassemble";
	}

	@Override
	public ArrayList<Object> getOpRepresentationList(int opIndex, InstructionContext context) {
		return null;
	}

	@Override
	public Address getAddress(int opIndex, InstructionContext context) {
		return null;
	}

	@Override
	public Scalar getScalar(int opIndex, InstructionContext context) {
		return null;
	}

	@Override
	public Register getRegister(int opIndex, InstructionContext context) {
		return null;
	}

	@Override
	public Object[] getOpObjects(int opIndex, InstructionContext context) {
		return new Object[0];
	}

	@Override
	public boolean hasDelimeter(int opIndex) {
		return false;
	}

	@Override
	public Object[] getInputObjects(InstructionContext context) {
		return new Object[0];
	}

	@Override
	public Object[] getResultObjects(InstructionContext context) {
		return new Object[0];
	}

	@Override
	public PcodeOp[] getPcode(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory) {
		return new PcodeOp[] { new PcodeOp(context.getAddress(), 0, PcodeOp.UNIMPLEMENTED) };
	}

	@Override
	public PackedBytes getPcodePacked(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory) {
		return null;
	}

	@Override
	public PcodeOp[] getPcode(InstructionContext context, int opIndex) {
		return new PcodeOp[0];
	}

	@Override
	public String getMnemonic(InstructionContext context) {
		return "BAD-Instruction";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getSeparator(int opIndex, InstructionContext context) {
		return null;
	}

	@Override
	public RefType getOperandRefType(int opIndex, InstructionContext context,
			PcodeOverride override, UniqueAddressFactory uniqueFactory) {
		return null;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public ParserContext getParserContext(MemBuffer buf, ProcessorContextView processorContext)
			throws MemoryAccessException {
		return this;
	}

	@Override
	public InstructionPrototype getPrototype() {
		return this;
	}

	@Override
	public int getDelaySlotByteCount() {
		return 0;
	}

	@Override
	public ParserContext getPseudoParserContext(Address addr, MemBuffer buffer,
			ProcessorContextView processorContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException, MemoryAccessException {
		return null;
	}
}
