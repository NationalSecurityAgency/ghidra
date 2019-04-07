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
package ghidra.app.cmd.comments;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.CodeUnitInfo;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Undoable edit for pasting code unit information at a location.
 * This class actually does the work of the "paste."
 */
public class CodeUnitInfoPasteCmd implements Command {

// TODO: should refactor to handle all variables in a consistent fashion

	private List<CodeUnitInfo> infoList;
	private Address startAddr;
	private StringBuilder messages = new StringBuilder();

	private boolean pasteLabels;
	private boolean pasteComments;

	/**
	 * Creates a new command for pasting comments/labels.
	 * @param startAddr starting address for info
	 * @param infoList list of CodeUnitInfo objects that will be applied
	 */
	public CodeUnitInfoPasteCmd(Address startAddr, List<CodeUnitInfo> infoList, boolean pasteLabels,
			boolean pasteComments) {
		this.startAddr = startAddr;
		this.infoList = infoList;
		this.pasteLabels = pasteLabels;
		this.pasteComments = pasteComments;
	}

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Paste Labels/Comments";
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		Program program = (Program) obj;
		SymbolTable symTable = program.getSymbolTable();
		Listing listing = program.getListing();
		boolean offCutExists = false;

		for (int i = 0; i < infoList.size(); i++) {
			CodeUnitInfo info = infoList.get(i);
			Address a = startAddr.add(info.getIndex());
			CodeUnit cu = listing.getCodeUnitAt(a);
			if (cu == null) {
				offCutExists = true;
				continue;
			}
			if (pasteLabels) {
				setFunction(listing, a, info);
				setLabel(listing, symTable, a, info);
			}
			if (pasteComments) {
				setComments(cu, a, info);
			}
		}

		if (offCutExists) {
			messages.append(
				"Could not paste some comments/labels - address not start of code unit");
			return false;
		}

		if (messages.length() != 0) {
			return false;
		}

		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return messages.toString();
	}

	/**
	 * Get the original function info and save it off in the undoMap;
	 * set the function info using the new info object.
	 * @param listing listing
	 * @param addr address of where to look for a function
	 * @param info new info to use
	 */
	private void setFunction(Listing listing, Address addr, CodeUnitInfo info) {
		Function function = listing.getFunctionAt(addr);
		if (function == null) {
			return;
		}

		String fnName = info.getFunctionName();
		if (fnName != null) {
			try {
				function.setName(fnName, info.getPrimarySymbolSource());
			}
			catch (DuplicateNameException e) {
				messages.append("Could not set function name--duplicate name: " + fnName).append(
					'\n');
			}
			catch (InvalidInputException e) {
				// shouldn't happen
			}
		}

//        String[] functionComments = info.getFunctionComments();
//        if (functionComments != null) {
//            StringBuffer sb = new StringBuffer();
//            for (int i=0; i<functionComments.length; i++) {
//                sb.append(functionComments[i]);
//                if (i <functionComments.length-1) {
//                    sb.append("\n");
//                }
//            }
//            String comment = sb.toString();
//        	String oldComment = function.getComment();
//        	if (oldComment != null && oldComment.length() != 0) {
//        		comment = oldComment + "\n" + comment;
//        	}
//            function.setComment(comment);
//        }

		String[] stackVarNames = info.getStackVariableNames();
		if (stackVarNames.length != 0) {
			String[] stackVarComments = info.getStackVariableComments();
			SourceType[] stackVarSources = info.getStackVariableSources();
			int[] stackOffsets = info.getStackOffsets();
			int[] stackVarFirstUseOffsets = info.getStackVarFirstUseOffsets();

			Variable[] stackVars = function.getVariables(VariableFilter.STACK_VARIABLE_FILTER);

			for (int i = 0; i < stackOffsets.length; i++) {
				Variable var = findStackVar(stackVars, stackOffsets[i], stackVarFirstUseOffsets[i]);
				if (var != null) {
					try {
						var.setName(stackVarNames[i], stackVarSources[i]);
					}
					catch (DuplicateNameException e) {
						messages.append(
							"Could not set stack variable name--duplicate name: " + fnName).append(
								'\n');
					}
					catch (InvalidInputException e) {
						// shouldn't happen
					}
					if (stackVarComments[i] != null) {
						var.setComment(stackVarComments[i]);
					}
				}
			}
		}

		String[] varNames = info.getVariableNames();
		if (varNames.length != 0) {
			String[] varComments = info.getVariableComments();
			SourceType[] varSources = info.getVariableSources();
			Address[] varAddrs = info.getVarAddresses();
			int[] regVarFirstUseOffsets = info.getVarFirstUseOffsets();

			Variable[] vars = function.getAllVariables();

			for (int i = 0; i < varAddrs.length; i++) {
				Variable var = findVar(vars, varAddrs[i], regVarFirstUseOffsets[i]);
				if (var != null) {
					try {
						var.setName(varNames[i], varSources[i]);
					}
					catch (DuplicateNameException e) {
						messages.append(
							"Could not set variable name--duplicate name: " + fnName).append('\n');
					}
					catch (InvalidInputException e) {
						// shouldn't happen
					}
					if (varComments[i] != null) {
						var.setComment(varComments[i]);
					}
				}
			}
		}
	}

	private Variable findStackVar(Variable[] stackVars, int stackOffset, int firstUseOffset) {
		for (int k = 0; k < stackVars.length; k++) {
			Variable var = stackVars[k];
			if (stackOffset == var.getStackOffset() && firstUseOffset == var.getFirstUseOffset()) {
				return var;
			}
		}
		return null;
	}

	private Variable findVar(Variable[] vars, Address storageAddr, int firstUseOffset) {
		for (int k = 0; k < vars.length; k++) {
			Variable var = vars[k];
			Varnode varnode = var.getVariableStorage().getFirstVarnode();
			if (varnode != null && firstUseOffset == var.getFirstUseOffset() &&
				storageAddr.equals(varnode.getAddress())) {
				return var;
			}
		}
		return null;
	}

	/**
	 * Set the label at the given address.
	 * @param symTable symbol table
	 * @param addr address for the label
	 * @param info object containing label and aliases
	 */
	private void setLabel(Listing listing, SymbolTable symTable, Address addr, CodeUnitInfo info) {

		if (!info.hasSymbols()) {
			return;
		}

		Function function = listing.getFunctionContaining(addr);
		Namespace scope = null;
		if (function != null) {
			scope = symTable.getNamespace(addr);
		}
		boolean functionExists = (function != null);

		// Copy primary symbol
		String primaryName = info.getPrimarySymbolName();
		if (primaryName != null) {
			Symbol s = symTable.getPrimarySymbol(addr);
			try {
				SourceType newSource = info.getPrimarySymbolSource();
				if (newSource != SourceType.DEFAULT) {
					// Only set the label if it is not a default label.
					if (s == null || (s.isDynamic()) ||
						(s.getSource() != SourceType.DEFAULT && !s.getName().equals(primaryName))) {
						s = symTable.createLabel(addr, primaryName, scope, newSource);
					}
					else {
						s.setName(primaryName, newSource);
					}
				}
			}
			catch (DuplicateNameException e) {
				messages.append("Could not set label name--duplicate name: " + primaryName).append(
					'\n');
			}
			catch (InvalidInputException e) {
				// should not happen
				Msg.error(this, "CodeUnitInfoEdit: Bad symbol name: '" + primaryName + "'", e);
				return;
			}
		}

		// Copy function scope symbols
		if (functionExists) {
			createSymbols(symTable, addr, info.getFunctionScopeSymbolNames(), scope,
				info.getFunctionScopeSymbolSources());
		}

		// Copy other symbols in the global scope
		createSymbols(symTable, addr, info.getOtherSymbolNames(), null,
			info.getOtherSymbolSources());
	}

	private void createSymbols(SymbolTable symTable, Address addr, String[] symbolNames,
			Namespace scope, SourceType[] symbolSources) {

		for (int i = 0; i < symbolNames.length; i++) {
			try {
				symTable.createLabel(addr, symbolNames[i], scope, symbolSources[i]);
			}
			catch (InvalidInputException e) {
				// should not happen
				Msg.error(this, "CodeUnitInfoEdit: Bad symbol name: '" + symbolNames[i] + "'", e);
			}
		}
//		Symbol s = symTable.getDynamicSymbol(addr);
//		if (s != null) {
//			symTable.removeSymbol(s);
//		}
	}

	/**
	 * Set the comments at the given address.
	 * @param cu code unit
	 * @param addr address of where to put the comments
	 * @param info info that has the comments to set
	 */
	private void setComments(CodeUnit cu, Address addr, CodeUnitInfo info) {

		String[] plateComment = info.getPlateComment();
		String[] preComment = info.getPreComment();
		String[] postComment = info.getPostComment();
		String[] eolComment = info.getEOLComment();
		String[] repeatableComment = info.getRepeatableComment();

		if (plateComment != null) {
			String[] oldComment = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
			cu.setCommentAsArray(CodeUnit.PLATE_COMMENT, appendComment(oldComment, plateComment));
		}
		if (preComment != null) {
			String[] oldComment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
			cu.setCommentAsArray(CodeUnit.PRE_COMMENT, appendComment(oldComment, preComment));
		}
		if (postComment != null) {
			String[] oldComment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
			cu.setCommentAsArray(CodeUnit.POST_COMMENT, appendComment(oldComment, postComment));
		}
		if (eolComment != null) {
			String[] oldComment = cu.getCommentAsArray(CodeUnit.EOL_COMMENT);
			cu.setCommentAsArray(CodeUnit.EOL_COMMENT, appendComment(oldComment, eolComment));
		}
		if (repeatableComment != null) {
			String[] oldComment = cu.getCommentAsArray(CodeUnit.REPEATABLE_COMMENT);
			cu.setCommentAsArray(CodeUnit.REPEATABLE_COMMENT,
				appendComment(oldComment, repeatableComment));
		}
	}

	/**
	 * Append comment2 onto comment1.
	 */
	private String[] appendComment(String[] comment1, String[] comment2) {
		// first check for duplicate comments
		ArrayList<String> list = new ArrayList<String>();
		for (int i = 0; i < comment2.length; i++) {
			list.add(comment2[i]);
		}
		for (int i = 0; i < comment1.length; i++) {
			for (int j = 0; j < list.size(); j++) {
				if (comment1[i].equals(list.get(j))) {
					list.remove(j);
					--j;
				}
			}
		}
		comment2 = new String[list.size()];
		comment2 = list.toArray(comment2);

		String[] comment = new String[comment1.length + comment2.length];
		System.arraycopy(comment1, 0, comment, 0, comment1.length);
		System.arraycopy(comment2, 0, comment, comment1.length, comment2.length);
		return comment;
	}

}
