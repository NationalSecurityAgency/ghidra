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
//
//Example script illustrating how to launch the Instruction Pattern Search dialog from a script.
//
//@category Search.InstructionPattern

import java.util.List;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.plugin.core.instructionsearch.model.MaskSettings;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.util.exception.InvalidInputException;

public class InstructionSearchScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		testLoadAddresses();
	}

	/**
	 * 
	 */
	@SuppressWarnings("unused")
	private void testSearcher() {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address min = addressFactory.getAddress("140017291");
		Address max = addressFactory.getAddress("140017294");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		InstructionSearchApi searcher = new InstructionSearchApi();

		// Search that masks out all operands.
		MaskSettings maskSettings = new MaskSettings(true, true, true);
		try {
			List<Address> results =
				searcher.search(currentProgram, addrSet.getFirstRange(), maskSettings);
			for (Address addr : results) {
				println(addr.toString());
			}

			// Search that masks nothing.
			results = searcher.search(currentProgram, addrSet.getFirstRange());
			for (Address addr : results) {
				println(addr.toString());
			}
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 */
	@SuppressWarnings("unused")
	private void testLoadString() {
		InstructionSearchApi searcher = new InstructionSearchApi();

		String bytes = "10011011";
		searcher.loadInstructions(bytes, state.getTool());
	}

	/**
	 * 
	 */
	private void testLoadAddresses() {
		InstructionSearchApi searcher = new InstructionSearchApi();

		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address min = addressFactory.getAddress("00400358");
		Address max = addressFactory.getAddress("0040036f");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		searcher.loadInstructions(addrSet, state.getTool());
	}

}
