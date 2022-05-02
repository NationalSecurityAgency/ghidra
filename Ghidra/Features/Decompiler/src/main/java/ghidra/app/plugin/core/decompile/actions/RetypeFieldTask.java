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

import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public abstract class RetypeFieldTask {
	protected Composite composite;
	protected DataType newType = null;
	protected DataType oldType;
	protected String errorMsg = null;		// Error to return if isValid returns false
	protected PluginTool tool;
	protected Program program;
	protected DecompilerProvider provider;
	protected ClangToken tokenAtCursor;

	public RetypeFieldTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangToken token, Composite composite) {
		this.tool = tool;
		this.program = program;
		this.provider = provider;
		this.tokenAtCursor = token;
		this.composite = composite;
	}

	/**
	 * @return the name to associate with the data-base transaction that actually changes the data-type
	 */
	public abstract String getTransactionName();

	/**
	 * Check if the selected field is valid for retyping.
	 * If there is a problem, the errorMsg is populated and false is returned.
	 * @return true if the field is valid
	 */
	public abstract boolean isValidBefore();

	/**
	 * Given a new data-type chosen by the user, check if the retype can proceed.
	 * If there is a problem, the errorMsg is populated and false is returned.
	 * @return true if the retype can proceed
	 */
	public abstract boolean isValidAfter();

	/**
	 * Assuming the transaction is started, do the work of changing the data-type.
	 * @throws IllegalArgumentException if there is a final error committing the data-type
	 */
	public abstract void commit() throws IllegalArgumentException;

	public void runTask() {
		if (!isValidBefore()) {
			Msg.showError(this, null, "Retype Failed", errorMsg);
			return;
		}
		newType = AbstractDecompilerAction.chooseDataType(tool, program, oldType);
		if (newType == null || newType.isEquivalent(oldType)) {
			return; // cancelled
		}

		int transaction = program.startTransaction(getTransactionName());
		try {
			DataTypeManager dtm = program.getDataTypeManager();
			newType = dtm.resolve(newType, null);
			if (!isValidAfter()) {
				Msg.showError(this, null, "Retype Failed",
					"Cannot retype field in '" + composite.getName() + "': " + errorMsg);
				return;
			}
			commit();
		}
		catch (IllegalArgumentException e) {
			Msg.showError(this, null, "Retype Failed",
				"Failed to retype field in '" + composite.getName() + "': " + e.getMessage(), e);
		}
		finally {
			program.endTransaction(transaction, true);
		}

	}
}
