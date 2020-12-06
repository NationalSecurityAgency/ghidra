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
package ghidra.app.plugin.core.checksums;

import java.io.InputStream;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

class MyTestMemoryBlock implements MemoryBlock {
	Address start;
	Address end;

	MyTestMemoryBlock(Address start, Address end) {
		this.start = start;
		this.end = end;
	}

	@Override
	public int getPermissions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public InputStream getData() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getStart() {
		return start;
	}

	@Override
	public Address getEnd() {
		return end;
	}

	@Override
	public long getSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isRead() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRead(boolean r) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isWrite() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setWrite(boolean w) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExecute() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExecute(boolean e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isVolatile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setVolatile(boolean v) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getSourceName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSourceName(String sourceName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlockType getType() {
		return MemoryBlockType.DEFAULT;
	}

	@Override
	public boolean isOverlay() {
		return false;
	}

	@Override
	public int compareTo(MemoryBlock block) {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.mem.MemoryBlock#isInitialized()
	 */
	@Override
	public boolean isInitialized() {
		return false;
	}

	@Override
	public boolean isMapped() {
		return false;
	}

	@Override
	public boolean isLoaded() {
		return start.getAddressSpace().isLoadedMemorySpace();
	}

	@Override
	public List<MemoryBlockSourceInfo> getSourceInfos() {
		throw new UnsupportedOperationException();
	}
}
