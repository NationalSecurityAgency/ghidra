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
/**
 * 
 */
package ghidra.app.util.opinion;

import static ghidra.program.model.pcode.AttributeId.*;

import java.util.HexFormat;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.*;

/**
 * Manager to hold byte information from the {@code <bytechunk>} tags inside the Decompiler Debug's 
 * XML.
 */
public class DecompileDebugByteManager {

	TaskMonitor monitor;
	Program prog;
	String programName;

	/**
	 * @param monitor TaskMonitor
	 * @param prog main program
	 * @param programName name of program
	 */
	public DecompileDebugByteManager(TaskMonitor monitor,
			Program prog, String programName) {
		this.monitor = monitor;
		this.prog = prog;
		this.programName = programName;
	}

	/**
	 * Parse the {@code <bytechunk>} tag - has the memory offset and the raw bytes
	 * 
	 * @param parser XmlPullParser
	 * @param log Xml
	 */
	public void parse(XmlPullParser parser, XmlMessageLog log) {

		while (parser.peek().getName().equals("bytechunk") && !monitor.isCancelled()) {
			processByteChunk(parser, log);
		}
	}

	/**
	 * Handle parsing and creating bytechunks and pulling out the byte string as a byte array.
	 * 
	 * @param parser XmlPullParser
	 * @param log XmlMessageLog
	 */
	private void processByteChunk(XmlPullParser parser, XmlMessageLog log) {

		XmlElement byteChunkElement = parser.start("bytechunk");
		Address address =
			prog.getAddressFactory()
					.getAddress(byteChunkElement.getAttribute(ATTRIB_OFFSET.name()));

		// end element contains the byte content
		byteChunkElement = parser.end(byteChunkElement);
		String hexString = byteChunkElement.getText().trim().replaceAll("\n", "");
		byte[] rawBytes = HexFormat.of().parseHex(hexString);

		if (!generateMemoryChunk(rawBytes, address, log)) {
			log.appendMsg("Error attempting to load memory chunk");
		}
	}

	/**
	 * Create memory blocks with the raw bytes from the central function and any other blocks
	 * such as for pointers or other data types that the Decompile.xml file was generated from. 
	 * 
	 * @param rawBytes raw program bytes
	 * @param address memory offset
	 * @param log XmlMessageLog
	 */
	private boolean generateMemoryChunk(byte[] rawBytes, Address address, XmlMessageLog log) {
		Memory memory = prog.getMemory();
		try {
			memory.createInitializedBlock(programName, address, rawBytes.length, (byte) 0,
				monitor, false);
			memory.setBytes(address, rawBytes);
		}
		catch (LockException | IllegalArgumentException | MemoryConflictException
				| AddressOverflowException | CancelledException | MemoryAccessException e) {
			log.appendException(e);
			return false;
		}
		return true;
	}

}
