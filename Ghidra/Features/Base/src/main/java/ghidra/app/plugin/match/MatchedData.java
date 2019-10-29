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
package ghidra.app.plugin.match;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

public class MatchedData {
	private final Program aProg;
	private final Program bProg;
	private final Address aAddr;
	private final Address bAddr;
	private final Data aData;
	private final Data bData;
	private final int aMatchNum;
	private final int bMatchNum;
	private final String reason;

	MatchedData(Program aProg, Program bProg, Address aAddr, Address bAddr, Data aData,
			Data bData, int aMatchNum, int bMatchNum, String reason) {
		this.aProg = aProg;
		this.bProg = bProg;
		this.aAddr = aAddr;
		this.bAddr = bAddr;
		this.aData = aData;
		this.bData = bData;
		this.aMatchNum = aMatchNum;
		this.bMatchNum = bMatchNum;
		this.reason = reason;
	}

	public Program getAProgram() {
		return aProg;
	}

	public Program getBProgram() {
		return bProg;
	}

	public Address getADataAddress() {
		return aAddr;
	}

	public Address getBDataAddress() {
		return bAddr;
	}

	public Data getAData() {
		return aData;
	}

	public Data getBData() {
		return bData;
	}

	public int getAMatchNum() {
		return aMatchNum;
	}

	public int getBMatchNum() {
		return bMatchNum;
	}

	public String getReason() {
		return reason;
	}
}
