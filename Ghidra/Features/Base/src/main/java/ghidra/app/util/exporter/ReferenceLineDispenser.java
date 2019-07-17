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
package ghidra.app.util.exporter;

import java.util.*;

import ghidra.app.util.XReferenceUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

class ReferenceLineDispenser extends AbstractLineDispenser {

	private static final Address[] EMPTY_ADDR_ARR = new Address[0];
	private final static String XREFS_DELIM = ",";

	private int headerWidth;
	private boolean displayRefHeader;
	private String header;
	private Memory memory;
	private ReferenceManager referenceManager;

	private List<String> lines = new ArrayList<String>();

	ReferenceLineDispenser() {
	}

	ReferenceLineDispenser(boolean forwardRefs, CodeUnit cu, Program program, ProgramTextOptions options) {
		this.memory  = program.getMemory();
		this.referenceManager = program.getReferenceManager();
		this.displayRefHeader = options.isShowReferenceHeaders();
		this.prefix = options.getCommentPrefix();
		this.header = (forwardRefs ? " FWD" : "XREF");
		this.headerWidth = options.getRefHeaderWidth();
		this.width = options.getRefWidth();
		this.fillAmount = options.getAddrWidth()
				+ options.getBytesWidth()
				+ options.getLabelWidth();
		this.isHTML = options.isHTML();

		Address [] refs    = (forwardRefs ? getForwardRefs(cu) : XReferenceUtil.getXRefList(cu));
		Address [] offcuts = (forwardRefs ? EMPTY_ADDR_ARR  : XReferenceUtil.getOffcutXRefList(cu));

		processRefs(cu.getMinAddress(), refs, offcuts);
	}

	ReferenceLineDispenser(Variable var, Program program, ProgramTextOptions options) {
		this.memory  = program.getMemory();
		this.referenceManager = program.getReferenceManager();
		this.displayRefHeader = options.isShowReferenceHeaders();
		this.header = "XREF";
		this.headerWidth = options.getRefHeaderWidth();
		this.prefix = options.getCommentPrefix();
		this.width = options.getStackVarXrefWidth();
		this.fillAmount = options.getStackVarPreNameWidth()
				+ options.getStackVarNameWidth()
				+ options.getStackVarDataTypeWidth()
				+ options.getStackVarOffsetWidth()
				+ options.getStackVarCommentWidth();
		this.isHTML = options.isHTML();

		List<Reference>   xrefs = new ArrayList<Reference>();
		List<Reference> offcuts = new ArrayList<Reference>();
		XReferenceUtil.getVariableRefs(var, xrefs, offcuts);
		Address[] xrefAddr = extractFromAddr(xrefs);
		Address[] offcutsAddr = extractFromAddr(offcuts);

		processRefs(var.getFunction().getEntryPoint(),
			xrefAddr, offcutsAddr);
	}

	private Address [] extractFromAddr(List<Reference> refs) {
		Address [] addrs = new Address[refs.size()];
		for (int i=0; i < addrs.length; i++) {
			addrs[i] = refs.get(i).getFromAddress();
		}
		Arrays.sort(addrs);
		return addrs;
	}

	@Override
	void dispose() {
		memory = null;
	}

	@Override
	boolean hasMoreLines() {
		return index < lines.size();
	}

	@Override
	String getNextLine() {
		if (hasMoreLines()) {
			return lines.get(index++);
		}
		return null;
	}

	////////////////////////////////////////////////////////////////////

	private Address [] getForwardRefs(CodeUnit cu) {
		boolean showRefs = false;

		Address cuAddr = cu.getMinAddress();
		Reference [] monRefs = cu.getMnemonicReferences();
		Reference primMonRef = referenceManager.getPrimaryReferenceFrom(cuAddr, CodeUnit.MNEMONIC);
		showRefs = (monRefs.length == 1 && primMonRef == null) || (monRefs.length > 1);

		if (!showRefs) {
			int opCount = cu.getNumOperands();
			for (int i = 0 ; i < opCount ; ++i) {
				Reference [] opRefs = cu.getOperandReferences(i);
				if (opRefs.length > 1) {
					showRefs = true;
					break;
				}
			}
		}

		if (!showRefs) {
			return EMPTY_ADDR_ARR;
		}

		Reference [] mRefs = cu.getReferencesFrom();
		Address [] refs = new Address[mRefs.length];
		for (int i = 0 ; i < mRefs.length ; ++i) {
			refs[i] = mRefs[i].getToAddress();
		}
		Arrays.sort(refs);
		return refs;
	}

	////////////////////////////////////////////////////////////////////

	private void processRefs(Address addr, Address [] refs, Address [] offcuts) {
		if (width < 1) {
			return;
		}
		if (refs.length == 0 && offcuts.length == 0) {
			return;
		}

		StringBuffer buf = new StringBuffer();

		Address [] all = new Address[refs.length + offcuts.length];
		System.arraycopy(   refs, 0, all,           0,   refs.length);
		System.arraycopy(offcuts, 0, all, refs.length, offcuts.length);

		if (displayRefHeader) {
			if (refs.length > 0 || offcuts.length > 0) {
				StringBuffer tmp = new StringBuffer();
				tmp.append(header);
				tmp.append("[");
				tmp.append(refs.length);
				tmp.append(",");
				tmp.append(offcuts.length);
				tmp.append("]: ");

				buf.append(clip(tmp.toString(), headerWidth));
			}
		}

		int refsPerLine = width / (all[0].toString().length() + XREFS_DELIM.length());
		int refsInCurrLine = 0;

		for (int i = 0; i < all.length; ++i) {
			//if we are not displaying the xref header,
			//then we need to append the comment prefix
			if (i == 0 && !displayRefHeader) {
				buf.append(getFill(headerWidth));
				buf.append(prefix);
			}
			//if we have started a new line, then
			//we need to append the comment prefix
			if (refsInCurrLine == 0 && i != 0) {
				buf.append(getFill(headerWidth));
				if (!displayRefHeader) {
					buf.append(prefix);
				}
			}
			//if we already appended a ref the line
			//and we are are about to append one more,
			//then we need the delim
			if (refsInCurrLine > 0) {
				buf.append(XREFS_DELIM);
			}

			//does memory contain this address? if so, then hyperlink it
			boolean isInMem = memory.contains(all[i]);
			if (isHTML && isInMem) {
				buf.append("<A HREF=\"#" + getUniqueAddressString(all[i]) + "\">");
			}
			buf.append(all[i].toString());
			if (isHTML && isInMem) {
				buf.append("</A>");
			}

			refsInCurrLine++;

			if (refsInCurrLine == refsPerLine) {
				lines.add((displayRefHeader ? prefix : "") + buf.toString());
				buf.delete(0, buf.length());
				refsInCurrLine = 0;
			}
		}

		if (refsInCurrLine > 0) {
			lines.add((displayRefHeader ? prefix : "") + buf.toString());
			buf.delete(0, buf.length());
		}
	}
}
