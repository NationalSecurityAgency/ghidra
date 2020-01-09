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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameVariableAction extends AbstractDecompilerAction {
	private final DecompilerController controller;
	private final PluginTool tool;
	private RenameTask nameTask = null;

	public RenameVariableAction(PluginTool tool, DecompilerController controller) {
		super("Rename Variable");
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Rename Variable" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
	}

	public static Address getStorageAddress(ClangToken tokenAtCursor,
			DecompilerController controller) {
		Varnode vnode = tokenAtCursor.getVarnode();
		Address storageAddress = null;
		if (vnode != null) {
			storageAddress = vnode.getAddress();
		}
		// op could be a PTRSUB, need to dig it out...
		else if (tokenAtCursor instanceof ClangVariableToken) {
			PcodeOp op = ((ClangVariableToken) tokenAtCursor).getPcodeOp();
			storageAddress =
				HighFunctionDBUtil.getSpacebaseReferenceAddress(controller.getProgram(), op);
		}
		return storageAddress;
	}

	/**
	 * Find the HighSymbol the decompiler associates with a specific address.
	 * @param addr is the specific address
	 * @param controller is the decompiler being queried
	 * @return the matching symbol or null if no symbol exists
	 */
	public static HighSymbol findHighSymbol(Address addr, DecompilerController controller) {
		HighSymbol highSymbol = null;
		HighFunction hfunc = controller.getDecompileData().getHighFunction();
		if (addr.isStackAddress()) {
			LocalSymbolMap lsym = hfunc.getLocalSymbolMap();
			highSymbol = lsym.findLocal(addr, null);
		}
		else {
			GlobalSymbolMap gsym = hfunc.getGlobalSymbolMap();
			highSymbol = gsym.getSymbol(addr);
		}
		return highSymbol;
	}

	/**
	 * Get the structure associated with a field token
	 * @param tok is the token representing a field
	 * @return the structure which contains this field
	 */
	public static Structure getStructDataType(ClangToken tok) {
		// We already know tok is a ClangFieldToken
		ClangFieldToken fieldtok = (ClangFieldToken) tok;
		DataType dt = fieldtok.getDataType();
		if (dt == null) {
			return null;
		}
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Structure) {
			return (Structure) dt;
		}
		return null;
	}

	/**
	 * Get the offset of the field within its structure
	 * @param tok is the display token associated with the field
	 * @return the offset, in bytes, of that field within its structure
	 */
	public static int getDataTypeOffset(ClangToken tok) {
		// Assume tok is already vetted as a structure carrying ClangFieldToken
		return ((ClangFieldToken) tok).getOffset();
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			DataType dt = getStructDataType(tokenAtCursor);
			if (dt == null) {
				return false;
			}
			getPopupMenuData().setMenuItemName("Rename Field");
			return true;
		}
		HighVariable variable = tokenAtCursor.getHighVariable();
		HighSymbol highSymbol = null;
		if (variable == null) {
			// Token may be from a variable reference, in which case we have to dig to find the actual symbol
			Address storageAddress = getStorageAddress(tokenAtCursor, controller);
			if (storageAddress == null) {
				return false;
			}
			highSymbol = findHighSymbol(storageAddress, controller);
		}
		else {
			highSymbol = variable.getSymbol();
		}
		if (highSymbol == null) {
			return false;
		}
		if (highSymbol.isGlobal()) {
			getPopupMenuData().setMenuItemName("Rename Global");
		}
		else {
			getPopupMenuData().setMenuItemName("Rename Variable");
		}
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		final ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		HighVariable variable = tokenAtCursor.getHighVariable();
		HighSymbol highSymbol = null;

		if (variable == null) {
			if (tokenAtCursor instanceof ClangVariableToken) {
				Address addr = getStorageAddress(tokenAtCursor, controller);
				highSymbol = findHighSymbol(addr, controller);
			}
		}
		else {
			highSymbol = variable.getSymbol();
		}
		if (highSymbol != null) {
			if (highSymbol.isGlobal()) {
				Address addr = null;
				if (highSymbol instanceof HighCodeSymbol) {
					addr = ((HighCodeSymbol) highSymbol).getStorage().getMinAddress();
				}
				if (addr == null || !addr.isMemoryAddress()) {
					Msg.showError(this, tool.getToolFrame(), "Rename Failed",
						"Memory storage not found for global variable");
					return;
				}
				nameTask = new RenameGlobalVariableTask(tool, tokenAtCursor.getText(), addr,
					controller.getProgram());
			}
			else {
				nameTask = new RenameVariableTask(tool, highSymbol, tokenAtCursor.getVarnode(),
					SourceType.USER_DEFINED);
			}
		}
		else if (tokenAtCursor instanceof ClangFieldToken) {
			Structure dt = getStructDataType(tokenAtCursor);
			if (dt == null) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed",
					"Could not find structure datatype");
				return;
			}
			int offset = getDataTypeOffset(tokenAtCursor);
			if (offset < 0 || offset >= dt.getLength()) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed",
					"Could not resolve field within structure");
				return;
			}
			nameTask = new RenameStructureFieldTask(tool, tokenAtCursor.getText(), dt, offset);
		}
		else {
			Msg.showError(this, tool.getToolFrame(), "Rename Failed",
				"Selected variable does not support renaming");
			return;
		}

		boolean dialogres = nameTask.runDialog();
		if (dialogres) {
			Program program = controller.getProgram();
			int transaction = program.startTransaction(nameTask.getTransactionName());
			boolean commit = false;
			try {
				nameTask.commit();
				commit = true;
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed", e.getMessage());
			}
			catch (InvalidInputException e) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed", e.getMessage());
			}
			finally {
				program.endTransaction(transaction, commit);
				controller.getDecompilerPanel().tokenRenamed(tokenAtCursor, nameTask.getNewName());
			}
		}
	}
}
