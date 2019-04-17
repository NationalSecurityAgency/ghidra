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
package ghidra.app.decompiler.component;

import java.util.*;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;

public class DecompilerUtils {

	/**
	 * If the token refers to an individual Varnode, return it. Otherwise return null;
	 * @return the Varnode or null otherwise
	 */
	public static Varnode getVarnodeRef(ClangToken vartoken) {
		if (vartoken == null) {
			return null;
		}
		if (vartoken instanceof ClangVariableToken) {
			Varnode res = vartoken.getVarnode();
			if (res != null) {
				return res;
			}
		}
		ClangNode parent = vartoken.Parent();
		if (parent instanceof ClangVariableDecl) {
			HighVariable high = ((ClangVariableDecl) parent).getHighVariable();
			parent = parent.Parent();
			if (parent instanceof ClangFuncProto && high != null) {
				Varnode[] instances = high.getInstances();
				for (Varnode instance : instances) {
					if (instance.isInput()) {
						return instance;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Construct the set of varnodes making up a simple forward slice of seed
	 * @param seed Varnode where the slice starts
	 * @return set of Varnodes in the slice
	 */
	public static Set<Varnode> getForwardSlice(Varnode seed) {
		HashSet<Varnode> varnodes = new HashSet<>();
		ArrayList<Varnode> worklist = new ArrayList<>();
		worklist.add(seed);

		for (int i = 0; i < worklist.size(); i++) {

			Varnode curvn = worklist.get(i);
			if (!varnodes.add(curvn)) {
				continue; // already processed
			}

			Iterator<PcodeOp> it = curvn.getDescendants();
			while (it.hasNext()) {
				PcodeOp op = it.next();
				if (op == null) {
					continue;
				}
				curvn = op.getOutput();
				if (curvn == null) {
					continue;
				}
				if (op.getOpcode() == PcodeOp.CALL) {
					continue;
				}
				if (op.getOpcode() == PcodeOp.CALLIND) {
					continue;
				}
				worklist.add(curvn);
			}
		}
		return varnodes;
	}

	public static Set<Varnode> getBackwardSlice(Varnode seed) {
		HashSet<Varnode> varnodes = new HashSet<>();
		ArrayList<Varnode> worklist = new ArrayList<>();
		worklist.add(seed);

		for (int i = 0; i < worklist.size(); i++) {

			Varnode curvn = worklist.get(i);
			if (!varnodes.add(curvn)) {
				continue; // already processed
			}

			PcodeOp op = curvn.getDef();
			if (op == null) {
				continue;
			}
			if (op.getOpcode() == PcodeOp.CALL) {
				continue;
			}
			if (op.getOpcode() == PcodeOp.CALLIND) {
				continue;
			}

			for (int j = 0; j < op.getNumInputs(); ++j) {
				curvn = op.getInput(j);
				if (curvn == null) {
					continue;
				}
				worklist.add(curvn);
			}
		}
		return varnodes;
	}

	public static Set<PcodeOp> getForwardSliceToPCodeOps(Varnode seed) {
		Set<Varnode> varnodes = new HashSet<>();
		Set<PcodeOp> pcodeops = new HashSet<>();
		List<Varnode> worklist = new ArrayList<>();
		worklist.add(seed);

		for (int i = 0; i < worklist.size(); i++) {

			Varnode curvn = worklist.get(i);
			if (!varnodes.add(curvn)) {
				continue; // already processed
			}

			Iterator<PcodeOp> it = curvn.getDescendants();
			while (it.hasNext()) {
				PcodeOp op = it.next();
				if (op == null) {
					continue;
				}

				pcodeops.add(op);
				curvn = op.getOutput();
				if (curvn == null) {
					continue;
				}
				if (op.getOpcode() == PcodeOp.CALL) {
					continue;
				}
				if (op.getOpcode() == PcodeOp.CALLIND) {
					continue;
				}

				worklist.add(curvn);
			}
		}
		return pcodeops;
	}

	public static Set<PcodeOp> getBackwardSliceToPCodeOps(Varnode seed) {
		Set<Varnode> varnodes = new HashSet<>();
		Set<PcodeOp> pcodeops = new HashSet<>();
		List<Varnode> worklist = new ArrayList<>();
		worklist.add(seed);

		for (int i = 0; i < worklist.size(); i++) {

			Varnode curvn = worklist.get(i);

			worklist.get(i);

			if (!varnodes.add(curvn)) {
				continue; // already processed
			}

			PcodeOp op = curvn.getDef();
			if (op == null) {
				continue;
			}

			pcodeops.add(op);
			if (op.getOpcode() == PcodeOp.CALL) {
				continue;
			}
			if (op.getOpcode() == PcodeOp.CALLIND) {
				continue;
			}

			for (int j = 0; j < op.getNumInputs(); ++j) {
				Varnode input = op.getInput(j);
				if (input == null) {
					continue;
				}
				worklist.add(input);
			}
		}
		return pcodeops;
	}

	/**
	 * @return the function referenced by the given token
	 */
	public static Function getFunction(Program program, ClangFuncNameToken token) {

		ClangNode parent = token.Parent();
		if (parent instanceof ClangFuncProto) {
			// decompiled function
			ClangFunction clangFunction = parent.getClangFunction();
			if (clangFunction != null) {
				return clangFunction.getHighFunction().getFunction();
			}
		}
		if (parent instanceof ClangStatement) {
			// sub-function call
			PcodeOp pcodeOp = token.getPcodeOp();
			if (pcodeOp != null && pcodeOp.getOpcode() == PcodeOp.CALL) {
				Address functionAddr = pcodeOp.getInput(0).getAddress();
				return program.getFunctionManager().getReferencedFunction(functionAddr);
			}
		}
		return null; // unhandled case
	}

	/**
	 * Find index of first field containing a ClangNode in tokenList
	 * @param tokenlist
	 * @return index of field, or -1
	 */
	public static int findIndexOfFirstField(List<ClangToken> tokenlist, Field[] fields) {
		for (int i = 0; i < fields.length; i++) {
			ClangTextField f = (ClangTextField) fields[i];
			List<ClangToken> tokenList = f.getTokens();
			for (int j = 0; j < tokenList.size(); j++) {
				ClangNode token = tokenList.get(j);
				if (tokenlist.contains(token)) {
					return i;
				}
			}
		}
		return -1;
	}

	/**
	 * Find all ClangNodes that have a minimum address in
	 * the AddressSetView
	 * @param reslist is resulting list of found ClangNodes
	 * @param parentNode is root of node tree to search
	 * @param aset is the AddressSetView to match
	 */
	public static List<ClangToken> getTokens(ClangNode root, AddressSetView addressSet) {
		List<ClangToken> tokenList = new ArrayList<>();
		collectTokens(tokenList, root, addressSet);
		return tokenList;
	}

	public static List<ClangToken> getTokens(ClangNode root, Address address) {
		List<ClangToken> tokenList = new ArrayList<>();
		collectTokens(tokenList, root, address);
		return tokenList;
	}

	private static void collectTokens(List<ClangToken> tokenList, ClangNode parentNode,
			Address address) {
		int nchild = parentNode.numChildren();
		for (int i = 0; i < nchild; i++) {
			ClangNode node = parentNode.Child(i);
			if (node.numChildren() > 0) {
				collectTokens(tokenList, node, address);
			}
			else if (node instanceof ClangToken) {
				ClangToken token = (ClangToken) node;
				if (intersects(token, address)) {
					tokenList.add((ClangToken) node);
				}
			}
		}
	}

	private static void collectTokens(List<ClangToken> tokenList, ClangNode parentNode,
			AddressSetView addressSet) {
		int nchild = parentNode.numChildren();
		for (int i = 0; i < nchild; i++) {
			ClangNode node = parentNode.Child(i);
			if (node.numChildren() > 0) {
				collectTokens(tokenList, node, addressSet);
			}
			else if (node instanceof ClangToken) {
				ClangToken token = (ClangToken) node;
				if (intersects(token, addressSet)) {
					tokenList.add((ClangToken) node);
				}
			}
		}
	}

	private static boolean intersects(ClangToken token, AddressSetView addressSet) {
		Address minAddress = token.getMinAddress();
		if (minAddress == null) {
			return false;
		}
		Address maxAddress = token.getMaxAddress();
		maxAddress = maxAddress == null ? minAddress : maxAddress;
		return addressSet.intersects(minAddress, maxAddress);
	}

	private static boolean intersects(ClangToken token, Address address) {
		Address minAddress = token.getMinAddress();
		if (minAddress == null) {
			return false;
		}
		Address maxAddress = token.getMaxAddress();
		if (maxAddress == null) {
			return minAddress.equals(maxAddress);
		}
		return address.compareTo(minAddress) >= 0 && address.compareTo(maxAddress) <= 0;
	}

	public static Address getClosestAddress(ClangToken token) {
		Address address = token.getMinAddress();
		if (address != null) {
			return address;
		}
		ClangToken addressedToken = findClosestAddressedToken(token);
		if (addressedToken == null) {
			return null;
		}
		return addressedToken.getMinAddress();
	}

	public static AddressSet findClosestAddressSet(Program program, AddressSpace functionSpace,
			List<ClangToken> tokenList) {
		AddressSet addressSet = new AddressSet();
		for (int i = 0; i < tokenList.size(); ++i) {
			ClangToken tok = tokenList.get(i);
			addTokenAddressRangeToSet(addressSet, tok, functionSpace);
		}

		// If no tokens are addressed - look for something on the same line
		if (addressSet.isEmpty()) {
			ClangLine lastLine = null;
			for (ClangToken token : tokenList) {
				// Only check each line once
				if (token.getLineParent() != lastLine) {
					lastLine = token.getLineParent();
					token = findClosestAddressedToken(token);
					addTokenAddressRangeToSet(addressSet, token, functionSpace);
				}
			}
		}
		return addressSet;

	}

	private static void addTokenAddressRangeToSet(AddressSet addrs, ClangToken token,
			AddressSpace space) {
		if (token == null || token.getMinAddress() == null) {
			return;
		}
		Address minAddress = token.getMinAddress();
		Address maxAddress = token.getMaxAddress();
		maxAddress = maxAddress == null ? minAddress : maxAddress;
		minAddress = space.getOverlayAddress(minAddress);
		maxAddress = space.getOverlayAddress(maxAddress);
		addrs.addRange(minAddress, maxAddress);
	}

	/**
	 * Find closest addressed token to a specified token or null if one is not found.
	 * Only adjacent tokens on the same line are examined.
	 * @param token
	 * @return closest addressed token
	 */
	private static ClangToken findClosestAddressedToken(ClangToken token) {
		if (token == null) {
			return null;
		}
		if (token.getMinAddress() != null) {
			return token;
		}

		List<ClangToken> lineTokens = token.getLineParent().getAllTokens();
		int tokIndex = -1;
		int lastIndex = lineTokens.size() - 1;
		for (int i = 0; i <= lastIndex; i++) {
			if (lineTokens.get(i) == token) {
				tokIndex = i;
				break;
			}
		}

		if (tokIndex != -1) {
			// look to the right
			for (int i = tokIndex + 1; i <= lastIndex; i++) {
				ClangToken tok = lineTokens.get(i);
				if (tok.getMinAddress() != null) {
					return tok;
				}
			}
			// look to the left
			for (int i = tokIndex - 1; i >= 0; i--) {
				ClangToken tok = lineTokens.get(i);
				if (tok.getMinAddress() != null) {
					return tok;
				}
			}
		}
		return null;
	}

	public static FieldSelection getFieldSelection(List<ClangToken> tokens) {
		FieldSelection fieldSelection = new FieldSelection();
		for (ClangToken clangToken : tokens) {
			ClangLine lineParent = clangToken.getLineParent();
			int lineNumber = lineParent.getLineNumber();
			// lineNumber is one-based, we need zero-based
			fieldSelection.addRange(lineNumber - 1, lineNumber);
		}
		return fieldSelection;
	}

	public static List<ClangToken> getTokensInSelection(FieldSelection selection, Field[] lines) {
		List<ClangToken> tokenList = new ArrayList<>();
		int numRanges = selection.getNumRanges();
		for (int i = 0; i < numRanges; i++) {
			FieldRange subSelectionRange = selection.getFieldRange(i);
			addTokensInSelectionRange(tokenList, subSelectionRange, lines);
		}
		return tokenList;
	}

	private static void addTokensInSelectionRange(List<ClangToken> tokenList,
			FieldRange selectionRange, Field[] lines) {

		FieldLocation start = selectionRange.getStart();
		FieldLocation end = selectionRange.getEnd();
		if (start.equals(end)) {
			return;
		}
		if (start.getIndex().intValue() == end.getIndex().intValue()) {
			// single row
			addTokens(tokenList, lines, start.getIndex().intValue(), start, end);
		}
		else {
			// add Tokens For First Line
			addTokens(tokenList, lines, start.getIndex().intValue(), start, null);

			// add Tokens for in between lines
			for (int i = start.getIndex().intValue() + 1; i < end.getIndex().intValue(); i++) {
				addTokens(tokenList, lines, i, null, null);
			}

			// add Tokens for last line
			addTokens(tokenList, lines, end.getIndex().intValue(), null, end);
		}

	}

	private static void addTokens(List<ClangToken> tokenList, Field[] lines, int lineNumber,
			FieldLocation start, FieldLocation end) {
		if (lineNumber >= lines.length) {
			return;
		}
		ClangTextField textLine = (ClangTextField) lines[lineNumber];
		int startIndex = getStartIndex(textLine, start);
		int endIndex = getEndIndex(textLine, end);
		tokenList.addAll(textLine.getTokens().subList(startIndex, endIndex));
	}

	private static int getStartIndex(ClangTextField textLine, FieldLocation location) {
		if (location == null) {
			return 0;
		}

		int tokenIndex = textLine.getTokenIndex(location);
		return tokenIndex;
	}

	private static int getEndIndex(ClangTextField textLine, FieldLocation location) {
		if (location == null) {
			return textLine.getTokens().size();
		}
		if (location.row == 0 && location.col == 0) {
			return 0;
		}

		int nextTokenIndex = textLine.getNextTokenIndexStartingAfter(location);
		return nextTokenIndex;
	}

	public static Address findAddressBefore(Field[] lines, ClangToken token) {
		ClangLine lineParent = token.getLineParent();
		int lineNumber = lineParent.getLineNumber();
		for (int i = lineNumber - 1; i >= 0; i--) {
			ClangTextField textLine = (ClangTextField) lines[i];
			List<ClangToken> tokens = textLine.getTokens();
			ClangToken addressedToken = findClosestAddressedToken(tokens.get(0));
			if (addressedToken != null) {
				return addressedToken.getMinAddress();
			}
		}
		return null;
	}

	public static ArrayList<ClangLine> toLines(ClangTokenGroup group) {

		List<ClangNode> alltoks = new ArrayList<>();
		group.flatten(alltoks);
		if (alltoks.isEmpty()) {
			return new ArrayList<>();
		}

		int i = 0;
		int lineNumber = 1;
		ClangBreak brk;
		ClangLine current;
		ArrayList<ClangLine> lines = new ArrayList<>();
		if (alltoks.get(0) instanceof ClangBreak) { // If first token is linebreak
			brk = (ClangBreak) alltoks.get(0);
			current = new ClangLine(lineNumber++, brk.getIndent()); // use its indent
			i += 1;
		}
		else {
			current = new ClangLine(lineNumber++, 0); // otherwise use zero indent
		}
		for (; i < alltoks.size(); ++i) {
			ClangToken tok = (ClangToken) alltoks.get(i);
			if (tok instanceof ClangBreak) {
				lines.add(current);
				brk = (ClangBreak) tok;
				current = new ClangLine(lineNumber++, brk.getIndent());
			}
			else {
				tok.setLineParent(current);
				current.addToken(tok);
			}
		}

		lines.add(current);
		return lines;
	}
}
