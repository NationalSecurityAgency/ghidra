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
//Finds programs containing various audio resources such as WAV's 
//@category Resources
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WAVEDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.List;

public class FindAudioInProgramScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		int totalFound = 0;
		//Look for potential file by checking for format byte patterns

		//look for WAV data types
		WAVEDataType wdt = new WAVEDataType();

		totalFound += findAudioData("WAV", wdt, WAVEDataType.MAGIC, WAVEDataType.MAGIC_MASK);

		if (totalFound == 0) {
			println("No Audio data found in " + currentProgram.getName());
			if (this.isRunningHeadless()) {
				currentProgram.setTemporary(true);
			}
		}

	}

	private int findAudioData(String dataName, DataType dt, byte[] pattern, byte[] mask) {

		println("Looking for " + dataName + "'s in " + currentProgram.getName());

		int numDataFound = 0;
		List<Address> foundList = scanForAudioData(pattern, mask);
		//Loop over all potential found WAVs
		for (int i = 0; i < foundList.size(); i++) {
			boolean foundData = false;
			//See if already applied WAV
			Data data = getDataAt(foundList.get(i));
			//If not already applied, try to apply WAV data type
			if (data == null) {
				println("Trying to apply " + dataName + " datatype at " +
					foundList.get(i).toString());

				try {
					Data newData = createData(foundList.get(i), dt);
					if (newData != null) {
						println("Applied WAV at " + newData.getAddressString(false, true));
						foundData = true;
					}
				}
				//If data does not apply correctly then it is not really that kind of data
				//Or it is bumping into other data
				catch (Exception e) {
					println("Invalid " + dataName + " at " + foundList.get(i).toString());
				}
			}
			else if (data.getMnemonicString().equals(dataName)) {
				println(dataName + " already applied at " + data.getAddressString(false, true));
				foundData = true;
			}

			//print found message only for those that apply correctly or were already applied
			if (foundData) {
				println("Found " + dataName + " in program " + currentProgram.getExecutablePath() +
					" at address " + foundList.get(i).toString());
				numDataFound++;
			}

		}
		return numDataFound;
	}

	List<Address> scanForAudioData(byte[] imageBytes, byte[] mask) {
		Memory memory = currentProgram.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		List<Address> foundImages = new ArrayList<Address>();

		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isInitialized()) {
				Address start = blocks[i].getStart();
				Address found = null;
				while (true) {
					if (monitor.isCancelled()) {
						break;
					}
					found =
						memory.findBytes(start, blocks[i].getEnd(), imageBytes, mask, true, monitor);
					if (found != null) {
						foundImages.add(found);
						start = found.add(1);
					}
					else
						break;
				}
			}
		}
		return foundImages;
	}
}
