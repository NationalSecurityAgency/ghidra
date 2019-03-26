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
//Trivial search for
//embedded binaries
//@category Binary

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

/**
 * EmbeddedFinder runs a trivial byte search across a file (input) and searches for potential embedded PE files (targets)
 * <p>
 * It will return an identified target if the target's NT header is where the DOS header says it should be
 * <p>
 * Currently this is the only sanity check it runs
 */
public class EmbeddedFinderScript extends GhidraScript {

	@Override
    public void run() throws Exception {
		byte[] MAGIC_DOS_HEADER = new byte[] { 0x4d, 0x5a };				// M Z
		byte[] MAGIC_NT_HEADER  = new byte[] { 0x50, 0x45, 0x00, 0x00 };	// P E 0x00 0x00

		List<Address> allFound = new ArrayList<Address>();

		Memory memory = currentProgram.getMemory();
		Address baseAddr = memory.getMinAddress();
		Address currAddr = baseAddr;

		while (currAddr != null) {
			// The purpose of breaking each check into small segments (where they could be combined)
			// is to make way for future file type support, keep code clean, and to encourage readability.
			boolean DOSExists = false;
			boolean NTExists = false;
			boolean DOSAgreesWithNT = false;

			Address DOS = memory.findBytes(currAddr, MAGIC_DOS_HEADER, null, true, getMonitor());
			if (DOS != null) {
				// IMAGE_DOS_HEADER is 128 bytes in length, so let's check if that much memory is available
				if (memory.contains(DOS.add(128)))
					DOSExists = true;
			}

			Address NT = memory.findBytes(DOS, MAGIC_NT_HEADER, null, true, getMonitor());
			if (NT != null) {
				// IMAGE_NT_HEADERS32 is 80 bytes in length, so let's check if that much memory is available
				if (memory.contains(NT.add(80)))
					NTExists = true;
			}

			if (DOSExists && NTExists) {
				// It would be better to import the proper structs rather than hard coding offsets.
				// However I'm unsure of what the best way of doing this would be. It's possible to include WINNT.h
				// but this requires the non-development environment to have access to it which makes things
				// less flexible and renders it brittle for future embedded target-type searches.
				// IMAGE_DOS_HEADER + 0x3c is the IMAGE_NT_HEADERS32 offset
				long impliedOffset = memory.getShort(DOS.add(0x3c));
				long actualOffset = NT.getAddressableWordOffset() - DOS.getAddressableWordOffset();
				if (impliedOffset == actualOffset)
					DOSAgreesWithNT = true;
			}

			if (DOSAgreesWithNT) {
				byte[] MAGIC_NT_HEADER_TEST = new byte[4];	// [TODO] Get this to dynamically pull correct size, not hardcoded
				memory.getBytes(NT, MAGIC_NT_HEADER_TEST);

				if (Arrays.equals(MAGIC_NT_HEADER, MAGIC_NT_HEADER_TEST)) {
					if (DOS != baseAddr)
						allFound.add(DOS);		// We only care about targets that are not also the parent file
				}
			}

			if (DOS != null)
				currAddr = DOS.add(1);	// Ensure next search doesn't overlap with current target
			else
				currAddr = null;
		}

		// Present user with target discovery(s)

		if (allFound.isEmpty())
			println("No embedded targets identified");
		else {
			println("Embedded targets identified");
			for (Address found : allFound)
				println("\t" + found.toString());
		}
    }
}
