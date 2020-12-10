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
package ghidra.pcode.exec;

import java.util.List;

import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeFrame {
	private final List<PcodeOp> code;
	private int index = 0;

	public PcodeFrame(List<PcodeOp> code) {
		this.code = code;
	}

	public int index() {
		return index;
	}

	public PcodeOp nextOp() {
		return code.get(advance());
	}

	public int advance() {
		return index++;
	}

	public boolean isFallThrough() {
		return index == code.size();
	}

	public boolean isBranch() {
		return index == -1;
	}

	public boolean isFinished() {
		return !(0 <= index && index < code.size());
	}

	public void branch(int rel) {
		index += rel - 1; // -1 because we already advanced
		if (!(0 <= index && index <= code.size())) {
			throw new LowlevelError("Bad p-code branch");
		}
	}

	public void finishAsBranch() {
		index = -1;
	}
}
