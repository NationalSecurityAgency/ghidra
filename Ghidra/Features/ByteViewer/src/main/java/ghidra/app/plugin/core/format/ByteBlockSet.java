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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.program.model.address.AddressSet;

/**
 * Interface to define methods for getting byte blocks and translating events.
 */
public interface ByteBlockSet {

	/**
	 * Get the blocks in this set.
	 * 
	 * @return the blocks
	 */
	public ByteBlock[] getBlocks();

	/**
	 * Get a plugin event for the given block and offset.
	 * 
	 * @param source source to use in the event
	 * @param block block to use to generate the event
	 * @param offset offset into the block
	 * @param column the column within the UI byte field
	 * @return the event
	 */
	public ProgramLocationPluginEvent getPluginEvent(String source, ByteBlock block,
			BigInteger offset, int column);

	/**
	 * Get the appropriate plugin event for the given block selection.
	 * 
	 * @param source source to use in the event
	 * @param selection selection to use to generate the event
	 * @return the event
	 */
	public ProgramSelectionPluginEvent getPluginEvent(String source, ByteBlockSelection selection);

	/**
	 * Return true if the block has been changed at the given index.
	 * 
	 * @param block byte block
	 * @param index offset into the block
	 * @param length number of bytes in question
	 * @return true if changed
	 */
	public boolean isChanged(ByteBlock block, BigInteger index, int length);

	/**
	 * Send a notification that a byte block edit occurred.
	 * 
	 * @param block block being edited
	 * @param index offset into the block
	 * @param oldValue old byte values
	 * @param newValue new byte values
	 */
	public void notifyByteEditing(ByteBlock block, BigInteger index, byte[] oldValue,
			byte[] newValue);

	/**
	 * Release resources that this object may be using.
	 */
	public void dispose();

	/**
	 * Convert the byte block selection to the address set it covers
	 * 
	 * @param selection the selection from the byte block perspective
	 * @return the selection from the address perspective
	 */
	public AddressSet getAddressSet(ByteBlockSelection selection);
}
