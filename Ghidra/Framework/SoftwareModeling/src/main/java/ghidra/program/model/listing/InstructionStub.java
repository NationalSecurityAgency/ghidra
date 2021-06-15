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
package ghidra.program.model.listing;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Saveable;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;

/**
 * InstructionStub can be extended for use by tests. It throws an UnsupportedOperationException
 * for all methods in the Instruction interface. Any method that is needed for your test can then 
 * be overridden so it can provide its own test implementation and return value.
 */
public class InstructionStub implements Instruction {

	@Override
	public String getAddressString(boolean showBlockName, boolean pad) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setProperty(String name, Saveable value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setProperty(String name, String value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setProperty(String name, int value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Saveable getObjectProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getStringProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getIntProperty(String name) throws NoValueException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean getVoidProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<String> propertyNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeProperty(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void visitProperty(PropertyVisitor visitor, String propertyName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getLabel() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol[] getSymbols() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getPrimarySymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMinAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMaxAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getMnemonicString() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment(int commentType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getCommentAsArray(int commentType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setComment(int commentType, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCommentAsArray(int commentType, String[] comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isSuccessor(CodeUnit codeUnit) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLength() {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] getBytes() throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void getBytesInCodeUnit(byte[] buffer, int bufferOffset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(Address testAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int compareTo(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addMnemonicReference(Address refAddr, RefType refType, SourceType sourceType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeMnemonicReference(Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getMnemonicReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getOperandReferences(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference getPrimaryReference(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addOperandReference(int index, Address refAddr, RefType type, SourceType sourceType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeOperandReference(int index, Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferencesFrom() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceIterator getReferenceIteratorTo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ExternalReference getExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPrimaryMemoryReference(Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setStackReference(int opIndex, int offset, SourceType sourceType, RefType refType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRegisterReference(int opIndex, Register reg, SourceType sourceType,
			RefType refType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumOperands() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getAddress(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Scalar getScalar(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getBytes(byte[] b, int memoryBufferOffset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Memory getMemory() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isBigEndian() {
		throw new UnsupportedOperationException();
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setValue(Register register, BigInteger value) throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRegisterValue(RegisterValue value) throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearRegister(Register register) throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getBaseContextRegister() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Register> getRegisters() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasValue(Register register) {
		throw new UnsupportedOperationException();
	}

	@Override
	public InstructionPrototype getPrototype() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object[] getOpObjects(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object[] getInputObjects() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object[] getResultObjects() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultOperandRepresentation(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Object> getDefaultOperandRepresentationList(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getSeparator(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getOperandType(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public RefType getOperandRefType(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getDefaultFallThroughOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getDefaultFallThrough() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getFallThrough() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getFallFrom() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] getFlows() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] getDefaultFlows() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FlowType getFlowType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isFallthrough() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasFallthrough() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FlowOverride getFlowOverride() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setFlowOverride(FlowOverride flowOverride) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PcodeOp[] getPcode() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PcodeOp[] getPcode(boolean includeOverrides) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PcodeOp[] getPcode(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getDelaySlotDepth() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInDelaySlot() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getNext() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getPrevious() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setFallThrough(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearFallThroughOverride() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isFallThroughOverridden() {
		throw new UnsupportedOperationException();
	}

	@Override
	public InstructionContext getInstructionContext() {
		throw new UnsupportedOperationException();
	}

}
