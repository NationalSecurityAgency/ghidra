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
package ghidra.app.plugin.core.debug.gui.pcode;

import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

public class OpPcodeRow implements PcodeRow {
	protected final Language language;
	protected final PcodeOp op;
	protected final boolean isNext;

	public OpPcodeRow(Language language, PcodeOp op, boolean isNext) {
		this.language = language;
		this.op = op;
		this.isNext = isNext;
	}

	@Override
	public int getSequence() {
		return op.getSeqnum().getTime();
	}

	@Override
	public String getCode() {
		return "<html>" + PcodeProgram.opToString(language, op, true) + "</html>";
	}

	public boolean isNext() {
		return isNext;
	}

	@Override
	public PcodeOp getOp() {
		return op;
	}
}
