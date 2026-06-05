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
package ghidra.lisa.pcode;

import ghidra.lisa.pcode.contexts.StatementContext;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.program.cfg.edge.*;
import it.unive.lisa.program.cfg.statement.Statement;

public class WorkItem {

	public enum PredType {
		TRUE,
		FALSE,
		SEQ
	}

	private Statement pred;
	private PredType type;
	private StatementContext context;

	public WorkItem(Statement pred, StatementContext ctx) {
		this.pred = pred;
		this.context = ctx;
		this.type = PredType.SEQ;
	}

	public StatementContext getContext() {
		return context;
	}

	public Statement getPred() {
		return pred;
	}

	public void setType(boolean val) {
		type = val ? PredType.TRUE : PredType.FALSE;
	}

	public Edge computeBranch(Statement succ) {
		PcodeLocation loc = (PcodeLocation) pred.getLocation();
		if (loc.getOpcode() == PcodeOp.RETURN) {
			return null;
		}
		return switch (getType()) {
			case TRUE -> new TrueEdge(pred, succ);
			case FALSE -> new FalseEdge(pred, succ);
			case SEQ -> new SequentialEdge(pred, succ);
			default -> throw new IllegalArgumentException("Unexpected value: " + getType());
		};
	}

	public PredType getType() {
		return type;
	}

	public String getKey() {
		String key = context.getOp().getSeqnum().toString();
		if (pred != null) {
			key = pred.getLocation().getCodeLocation() + "=>" + key;
		}
		return key;
	}
}
