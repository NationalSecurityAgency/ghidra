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

import ghidra.app.util.XReferenceUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

class ReferenceLineDispenser extends AbstractLineDispenser {

	private final static String XREFS_DELIM = ",";

	private int headerWidth;
	private boolean displayRefHeader;
	private String header;
	private Memory memory;
	private ReferenceManager referenceManager;
	private boolean forwardRefs;

	private List<String> lines = new ArrayList<>();

	ReferenceLineDispenser() {
	}

	ReferenceLineDispenser(boolean forwardRefs, CodeUnit cu, Program program,
			ProgramTextOptions options) {
		this.memory = program.getMemory();
		this.referenceManager = program.getReferenceManager();
		this.displayRefHeader = options.isShowReferenceHeaders();
		this.prefix = options.getCommentPrefix();
		this.header = (forwardRefs ? " FWD" : "XREF");
		this.headerWidth = options.getRefHeaderWidth();
		this.width = options.getRefWidth();
		this.fillAmount =
			options.getAddrWidth() + options.getBytesWidth() + options.getLabelWidth();
		this.isHTML = options.isHTML();
		this.forwardRefs = forwardRefs;

		List<Reference> refs = (forwardRefs ? getForwardRefs(cu) : getXRefList(cu));
		List<Reference> offcuts = (forwardRefs ? List.of() : getOffcutXRefList(cu));
		processRefs(cu.getMinAddress(), refs, offcuts);
	}

	ReferenceLineDispenser(Variable var, Program program, ProgramTextOptions options) {
		this.memory = program.getMemory();
		this.referenceManager = program.getReferenceManager();
		this.displayRefHeader = options.isShowReferenceHeaders();
		this.header = "XREF";
		this.headerWidth = options.getRefHeaderWidth();
		this.prefix = options.getCommentPrefix();
		this.width = options.getStackVarXrefWidth();
		this.fillAmount = options.getStackVarPreNameWidth() + options.getStackVarNameWidth() +
			options.getStackVarDataTypeWidth() + options.getStackVarOffsetWidth() +
			options.getStackVarCommentWidth();
		this.isHTML = options.isHTML();
		this.forwardRefs = false;

		List<Reference> xrefs = new ArrayList<>();
		List<Reference> offcuts = new ArrayList<>();
		XReferenceUtils.getVariableRefs(var, xrefs, offcuts);

		Comparator<? super Reference> comparator = (r1, r2) -> {
			return r1.getFromAddress().compareTo(r2.getFromAddress());
		};
		xrefs.sort(comparator);
		offcuts.sort(comparator);

		processRefs(var.getFunction().getEntryPoint(), xrefs, offcuts);
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

	private List<Reference> getForwardRefs(CodeUnit cu) {
		boolean showRefs = false;

		Address cuAddr = cu.getMinAddress();
		Reference[] monRefs = cu.getMnemonicReferences();
		Reference primMonRef = referenceManager.getPrimaryReferenceFrom(cuAddr, CodeUnit.MNEMONIC);
		showRefs = (monRefs.length == 1 && primMonRef == null) || (monRefs.length > 1);

		if (!showRefs) {
			int opCount = cu.getNumOperands();
			for (int i = 0; i < opCount; ++i) {
				Reference[] opRefs = cu.getOperandReferences(i);
				if (opRefs.length > 1) {
					showRefs = true;
					break;
				}
			}
		}

		if (!showRefs) {
			return List.of();
		}

		List<Reference> refs = Arrays.asList(cu.getReferencesFrom());
		refs.sort((r1, r2) -> {
			return r1.getToAddress().compareTo(r2.getToAddress());
		});
		return refs;
	}

	private void processRefs(Address addr, List<Reference> refs,
			List<Reference> offcuts) {

		if (width < 1) {
			return;
		}
		if (refs.isEmpty() && offcuts.isEmpty()) {
			return;
		}

		StringBuilder buf = new StringBuilder();
		List<Reference> all = new ArrayList<>();
		all.addAll(refs);
		all.addAll(offcuts);

		if (displayRefHeader) {
			if (!refs.isEmpty() || !offcuts.isEmpty()) {

				String text;
				if (!offcuts.isEmpty()) {
					text = "%s[%d,%d]: ".formatted(header, refs.size(), offcuts.size());
				}
				else {
					text = "%s[%d]: ".formatted(header, refs.size());
				}
				buf.append(clip(text, headerWidth));
			}
		}
		else {
			buf.append(getFill(headerWidth));
			buf.append(prefix);
		}

		int currentXrefWidth = 0;
		for (int i = 0; i < all.size(); ++i) {

			// does memory contain this address? if so, then hyperlink it
			Reference ref = all.get(i);
			XrefItem xrefItem = new XrefItem(ref);

			int nextWidth = currentXrefWidth + xrefItem.getDisplayableWidth();
			if (nextWidth > width) {
				// line is too long for the current xref, break
				lines.add(prefix + buf.toString());
				buf.delete(0, buf.length());

				// since we already have the next xref, add the next line's prefix
				buf.append(getFill(headerWidth));

				currentXrefWidth = 0;
			}

			currentXrefWidth += xrefItem.getDisplayableWidth();
			buf.append(xrefItem.getRawText());

			if (i < all.size() - 1) {
				buf.append(XREFS_DELIM);
			}
		}

		// add the last xref line
		if (buf.length() != 0) {
			lines.add(prefix + buf.toString());
		}
	}

	// copied from XRefFieldFactory
	private String getRefTypeDisplayString(Reference reference) {

		if (reference.getReferenceType().isRead() && reference.getReferenceType().isWrite()) {
			return "(RW)";
		}

		RefType refType = reference.getReferenceType();
		if (reference instanceof ThunkReference) {
			return "(T)";
		}
		if (refType instanceof DataRefType) {
			if (refType.isRead() || refType.isIndirect()) {
				return "(R)";
			}
			else if (refType.isWrite()) {
				return "(W)";
			}
			else if (refType.isData()) {
				return "(*)";
			}
		}
		if (refType.isCall()) {
			return "(c)";
		}
		else if (refType.isJump()) {
			return "(j)";
		}
		return "";
	}

	public static List<Reference> getXRefList(CodeUnit cu) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return List.of();
		}

		// default value taken from XRefFieldFactory
		int maxXrefs = 20;
		List<Reference> refs = XReferenceUtils.getXReferences(cu, maxXrefs + 1);
		int maxOffcuts = Math.max(0, maxXrefs - refs.size());
		List<Reference> offcuts = XReferenceUtils.getOffcutXReferences(cu, maxOffcuts);
		refs.addAll(offcuts);
		refs.sort((r1, r2) -> {
			return r1.getFromAddress().compareTo(r2.getFromAddress());
		});
		return refs;
	}

	private static List<Reference> getOffcutXRefList(CodeUnit cu) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return List.of();
		}

		List<Reference> offcutList = new ArrayList<>();
		// Lookup the offcut xrefs...
		//
		if (cu.getLength() > 1) {
			ReferenceManager refMgr = prog.getReferenceManager();
			AddressSet set =
				new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
			AddressIterator iter = refMgr.getReferenceDestinationIterator(set, true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				ReferenceIterator refIter = refMgr.getReferencesTo(addr);
				while (refIter.hasNext()) {
					Reference ref = refIter.next();
					offcutList.add(ref);
				}
			}
		}

		offcutList.sort((r1, r2) -> {
			return r1.getFromAddress().compareTo(r2.getFromAddress());
		});
		return offcutList;
	}

	private class XrefItem {
		private Address address;
		private String displayableString;

		XrefItem(Reference ref) {
			address = forwardRefs ? ref.getToAddress() : ref.getFromAddress();
			String refType = getRefTypeDisplayString(ref);
			this.displayableString = address.toString() + refType;
		}

		int getDisplayableWidth() {
			return displayableString.length();
		}

		String getRawText() {
			boolean isInMem = memory.contains(address);
			if (isHTML && isInMem) {
				String href = getUniqueAddressString(address);
				return "<A HREF=\"#%s\">%s</A>".formatted(href, displayableString);
			}

			return displayableString;
		}
	}
}
