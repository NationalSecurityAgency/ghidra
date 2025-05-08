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
package ghidra.app.plugin.core.decompiler.taint;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

public class TaintLabel {

	private MarkType mtype;
	private ClangToken token;

	private String fname;
	private HighFunction hfun;
	private HighVariable hvar;
	private Varnode vnode;
	private boolean active;
	private String label;
	private boolean isGlobal = false;
	private boolean bySymbol = false;

	// TODO: This is not a good identifier since it could change during re work!
	private Address addr;
	private ClangLine clangLine;
	private int size = 0;

	public TaintLabel(MarkType mtype, ClangToken token) throws PcodeException {
	
		HighVariable highVar = token.getHighVariable();
		if (highVar == null) {
			hfun = token.getClangFunction().getHighFunction();
		}
		else {
			hfun = highVar.getHighFunction();
			HighSymbol symbol = highVar.getSymbol();
			if (symbol != null) {
				isGlobal = symbol.isGlobal();
			}
		}

		this.vnode = token.getVarnode();
		if (vnode != null) { // The user pointed at a particular usage, not just the vardecl			
			HighVariable high = vnode.getHigh();
			if (high instanceof HighLocal) {
				highVar = hfun.splitOutMergeGroup(high, vnode);
			}
		}

		String fn = token instanceof ClangFuncNameToken ftoken ? ftoken.getText()
				: hfun.getFunction().getName();
		PcodeOp pcodeOp = token.getPcodeOp();
		Address target = pcodeOp == null ? hfun.getFunction().getEntryPoint() : pcodeOp.getSeqnum().getTarget();
		if (vnode == null && pcodeOp != null) {
			vnode = pcodeOp.getOutput();
			highVar = vnode.getHigh();
		}
		
		this.mtype = mtype;
		this.token = token;
		this.fname = fn;
		this.hvar = highVar;
		this.active = true;
		this.addr = target;
		if (hvar != null) {
			size = hvar.getSize();
		}
		this.clangLine = token.getLineParent();

		// Initial label is one of SOURCE, SINK, or GATE
		this.label = mtype.toString();
	}

	public ClangLine getClangLine() {
		return this.clangLine;
	}

	public void setClangLine(ClangLine clangLine) {
		this.clangLine = clangLine;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getLabel() {
		return label;
	}

	public MarkType getType() {
		return this.mtype;
	}

	public ClangToken getToken() {
		return this.token;
	}

	public HighFunction getHighFunction() {
		return this.hfun;
	}

	public String getFunctionName() {
		return this.fname;
	}

	public HighVariable getHighVariable() {
		return this.hvar;
	}

	public Address getAddress() {
		return addr;
	}

	@Override
	public String toString() {
		String result = mtype.toString() + " ";

		if (isActive()) {
			result += "[ACTIVE]: ";
		}
		else {
			result += "[INACTIVE]: ";
		}

		result = result + fname;
		if (this.hvar != null) {
			result += ", " + this.hvar.toString();
		}

		if (this.clangLine != null) {
			result += ", " + this.clangLine.toString();
		}

		return result;
	}

	public void deactivate() {
		active = false;
	}

	public void activate() {
		active = true;
	}
	
	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public void toggle() {
		active = !active;
	}

	public boolean isActive() {
		return active;
	}

	public boolean isGlobal() {
		return isGlobal;
	}

	public boolean bySymbol() {
		return bySymbol;
	}

	public void setBySymbol(boolean bySymbol) {
		this.bySymbol = bySymbol;
	}

	public boolean hasHighVar() {
		return this.hvar != null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * hashCode that ignores the boolean active status.
	 */
	@Override
	public int hashCode() {
		int prime = 31;
		int result = 1;
		result = prime * result + mtype.hashCode();
		result = prime * result + fname.hashCode();
		if (hvar != null) {
			result = prime * result + hvar.hashCode();
		}
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null) {
			return false;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		TaintLabel other = (TaintLabel) o;
		if (this.mtype != other.mtype) {
			return false;
		}
		if (!this.fname.equals(other.fname)) {
			return false;
		}
		if (this.hvar != other.hvar) {
			return false;
		}
		return true;
	}
	
	public Address getVarnodeAddress() {
		if (vnode != null) {
			return vnode.getAddress();
		}
		return null;
	}

}
