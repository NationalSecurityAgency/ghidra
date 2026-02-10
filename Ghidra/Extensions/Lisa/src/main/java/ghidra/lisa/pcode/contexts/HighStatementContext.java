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
package ghidra.lisa.pcode.contexts;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;

public class HighStatementContext extends StatementContext {

	// High pcode-only
	private HighFunction hfunc;
	private HighStatementContext prev;
	private HighStatementContext succ;
	private List<StatementContext> branches = new ArrayList<>();
	

	public HighStatementContext(HighFunction hfunc, PcodeOp op) {
		super(op);
		this.hfunc = hfunc; 
	}

	@Override
	public String toString() {
		return op.getSeqnum() + ": " + op;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return hfunc.getAddressFactory();
	}

	public HighStatementContext getPrev() {
		 return prev;
	}
	
	public void setPrev(HighStatementContext ctx) {
		this.prev = ctx;
	}

	public HighStatementContext getNext() {
		 return succ;
	}
	
	public void setNext(HighStatementContext ctx) {
		this.succ = ctx;
	}

	public List<StatementContext> getBranches() {
		return branches;
	}

	public void addBranch(HighStatementContext ctx) {
		branches.add(ctx);
	}

}
