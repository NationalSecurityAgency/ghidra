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
package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;

public abstract class SymbolTreeContextAction extends DockingAction {

	public SymbolTreeContextAction(String name, String owner) {
		super(name, owner);
	}

	public SymbolTreeContextAction(String name, String owner, KeyBindingType kbType) {
		super(name, owner, kbType);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof SymbolTreeActionContext)) {
			return false;
		}
		SymbolTreeActionContext context = (SymbolTreeActionContext) actionContext;
		if (context.getProgram() == null) {
			return false;
		}
		return isEnabledForContext(context);
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((SymbolTreeActionContext) context);
	}

	@Override
	public final boolean isValidContext(ActionContext context) {
		if (!(context instanceof SymbolTreeActionContext)) {
			return false;
		}
		return isValidContext((SymbolTreeActionContext) context);
	}

	@Override
	public final boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof SymbolTreeActionContext)) {
			return false;
		}
		return isAddToPopup((SymbolTreeActionContext) context);
	}

	protected boolean isAddToPopup(SymbolTreeActionContext context) {
		return isEnabledForContext(context);
	}

	protected boolean isValidContext(SymbolTreeActionContext context) {
		return true;
	}

	protected boolean isEnabledForContext(SymbolTreeActionContext context) {
		TreePath[] selectedSymbolTreePaths = context.getSelectedSymbolTreePaths();
		return selectedSymbolTreePaths != null && selectedSymbolTreePaths.length != 0;
	}

	protected abstract void actionPerformed(SymbolTreeActionContext context);

}
