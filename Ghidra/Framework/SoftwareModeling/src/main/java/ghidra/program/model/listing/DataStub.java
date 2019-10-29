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

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeDisplayOptions;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Saveable;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;

/**
 * DataStub can be extended for use by tests. It throws an UnsupportedOperationException
 * for all methods in the Data interface. Any method that is needed for your test can then
 * be overridden so it can provide its own test implementation and return value.
 */
public class DataStub implements Data {

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
	public void addOperandReference(int index, Address refAddr, RefType type,
			SourceType sourceType) {
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
	public Long getLong(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getString(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] getByteArray(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getValue(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLong(String name, long value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setString(String name, String value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setByteArray(String name, byte[] value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setValue(String name, Object value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearSetting(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearAllSettings() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEmpty() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Settings getDefaultSettings() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Class<?> getValueClass() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasStringValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isConstant() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isVolatile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDefined() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getBaseDataType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getValueReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addValueReference(Address refAddr, RefType type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeValueReference(Address refAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getFieldName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComponentPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPointer() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUnion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isStructure() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isArray() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDynamic() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getParent() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getRoot() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getRootOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getParentOffset() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getComponent(int index) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getComponent(int[] componentPath) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int[] getComponentPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumComponents() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getComponentAt(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Data> getComponentsContaining(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getPrimitiveAt(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getComponentIndex() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getComponentLevel() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultValueRepresentation() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultLabelPrefix(DataTypeDisplayOptions options) {
		throw new UnsupportedOperationException();
	}

}
