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
package ghidra.app.plugin.core.byteviewer;

import java.math.BigInteger;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.format.*;
import ghidra.program.model.address.AddressSet;

public class EmptyByteBlockSet implements ByteBlockSet {

	@Override
	public void dispose() {
	}

	@Override
	public ByteBlock[] getBlocks() {
		return new ByteBlock[0];
	}

	@Override
	public ProgramLocationPluginEvent getPluginEvent(String source, ByteBlock block,
			BigInteger offset, int column) {
		return null;
	}

	@Override
	public ProgramSelectionPluginEvent getPluginEvent(String source, ByteBlockSelection selection) {
		return null;
	}

	@Override
	public boolean isChanged(ByteBlock block, BigInteger index, int length) {
		return false;
	}

	@Override
	public void notifyByteEditing(ByteBlock block, BigInteger index, byte[] oldValue,
			byte[] newValue) {
	}

	@Override
	public AddressSet getAddressSet(ByteBlockSelection selection) {
		return null;
	}
}
