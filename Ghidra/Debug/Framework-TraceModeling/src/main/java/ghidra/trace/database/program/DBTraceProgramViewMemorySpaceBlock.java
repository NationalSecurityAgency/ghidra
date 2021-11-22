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
package ghidra.trace.database.program;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

public class DBTraceProgramViewMemorySpaceBlock extends AbstractDBTraceProgramViewMemoryBlock {

	private final AddressSpace space;

	public DBTraceProgramViewMemorySpaceBlock(DBTraceProgramView program, AddressSpace space) {
		super(program);
		this.space = space;
	}

	@Override
	protected String getInfoDescription() {
		return "Trace space: " + space;
	}

	@Override
	protected AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public Address getStart() {
		return space.getMinAddress();
	}

	@Override
	public Address getEnd() {
		return space.getMaxAddress();
	}

	@Override
	public int getPermissions() {
		return MemoryBlock.READ | MemoryBlock.WRITE | MemoryBlock.EXECUTE;
	}

	@Override
	public String getName() {
		return space.getName();
	}

	@Override
	public void setName(String name) throws IllegalArgumentException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isRead() {
		return true;
	}

	@Override
	public void setRead(boolean r) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isWrite() {
		return true;
	}

	@Override
	public void setWrite(boolean w) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExecute() {
		return true;
	}

	@Override
	public void setExecute(boolean e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isVolatile() {
		return false;
	}

	@Override
	public void setVolatile(boolean v) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getSourceName() {
		return "Trace"; // TODO: What does this method actually do?
	}

	@Override
	public void setSourceName(String sourceName) {
		throw new UnsupportedOperationException();
	}
}
