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

import java.util.*;

import ghidra.lisa.pcode.WorkItem.PredType;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.controlFlow.ControlFlowStructure;
import it.unive.lisa.program.cfg.edge.Edge;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.util.datastructures.graph.code.NodeList;

public class PcodeBranch extends ControlFlowStructure {

	private Statement branch;
	private Statement fallThrough;

	protected PcodeBranch(NodeList<CFG, Statement, Edge> cfgMatrix, Statement condition) {
		super(cfgMatrix, condition, null);
	}

	@Override
	protected Collection<Statement> bodyStatements() {
		Collection<Statement> all = new HashSet<>(getTrueBranch());
		all.addAll(getFalseBranch());
		return all;
	}

	private Collection<Statement> getFalseBranch() {
		if (fallThrough == null) {
			return Set.of();
		}
		return new HashSet<>(cfgMatrix.followersOf(fallThrough));
	}

	private Collection<Statement> getTrueBranch() {
		if (branch == null) {
			return Set.of();
		}
		return new HashSet<>(cfgMatrix.followersOf(branch));
	}

	@Override
	public boolean contains(Statement st) {
		return bodyStatements().contains(st);
	}

	@Override
	public void simplify() {
		// Nothing required here
	}

	@Override
	public String toString() {
		return "if-then-else[" + getCondition() + "]";
	}

	@Override
	public Collection<Statement> getTargetedStatements() {
		return bodyStatements();
	}

	public void addStatement(Statement st, PredType type) {
		if (type.equals(PredType.TRUE)) {
			branch = st;
		}
		else {
			fallThrough = st;
			setFirstFollower(st);
		}
	}

	public Statement getBranch() {
		return branch;
	}

	public Statement getFallThrough() {
		return fallThrough;
	}

}
