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
import java.util.Map;

import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeFrame {
	private final Language language;
	private final List<PcodeOp> code;
	private final Map<Integer, String> useropNames;

	private int index = 0;
	private int branched = -1;

	/**
	 * Construct a frame of p-code execution
	 * 
	 * <p>
	 * The passed in code should be an immutable list. It is returned directly by
	 * {@link #getCode()}, which would otherwise allow mutation. The frame does not create its own
	 * immutable copy as a matter of efficiency. Instead, the provider of the code should create an
	 * immutable copy, probably once, e.g., when compiling a {@link PcodeProgram}.
	 * 
	 * @param language the language to which the program applies
	 * @param code the program's p-code
	 * @param useropNames a map of additional sleigh/p-code userops linked to the program
	 */
	public PcodeFrame(Language language, List<PcodeOp> code, Map<Integer, String> useropNames) {
		this.language = language;
		this.code = code;
		this.useropNames = useropNames;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("<p-code frame: index=");
		sb.append(index);
		if (branched != -1) {
			sb.append(" branched=" + branched);
		}
		sb.append(" {");
		for (int i = 0; i < code.size(); i++) {
			sb.append("\n");
			if (i == branched) {
				sb.append(" *>");
			}
			else if (i == index) {
				sb.append(" ->");
			}
			else {
				sb.append("   ");
			}
			PcodeOp op = code.get(i);
			sb.append(op.getSeqnum() + ": " + PcodeProgram.opToString(language, op, false));
		}
		if (index == code.size()) {
			sb.append("\n *> fall-through");
		}
		sb.append("\n}>");
		return sb.toString();
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

	public int stepBack() {
		return index--;
	}

	public String getUseropName(int userop) {
		return useropNames.get(userop);
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
		branched = index - 1; // -1 because we already advanced
		index = -1;
	}

	public List<PcodeOp> getCode() {
		return code;
	}

	public PcodeOp[] copyCode() {
		return code.toArray(PcodeOp[]::new);
	}

	/**
	 * Get the index of the last (branch) op executed
	 * 
	 * <p>
	 * The behavior here is a bit strange for compatibility with the established concrete emulator.
	 * If the program (instruction) completed with fall-through, then this will return -1. If it
	 * completed on a branch, then this will return the index of that branch.
	 * 
	 * @return
	 */
	public int getBranched() {
		return branched;
	}
}
