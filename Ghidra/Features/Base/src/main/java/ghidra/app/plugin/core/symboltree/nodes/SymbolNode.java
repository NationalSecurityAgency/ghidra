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
package ghidra.app.plugin.core.symboltree.nodes;

import java.awt.datatransfer.DataFlavor;
import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.datastruct.AlphaNumericComparator;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class SymbolNode extends SymbolTreeNode {

	protected final Program program;
	protected final Symbol symbol;

	private String cachedDisplayName;
	private boolean isCut;

	SymbolNode(Program program, Symbol symbol) {
		super();
		this.program = program;
		this.symbol = symbol;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		List<GTreeNode> list = new ArrayList<>();

		if (program.isClosed()) {
			return list;
		}
		SymbolTreeFilterState filterState = getFilterState();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getChildren(symbol);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				return Collections.emptyList();
			}

			Symbol s = iter.next();
			if (filterState.passesFilter(s)) {
				list.add(createNode(s, program));
			}
		}

		sort(list);

		return list;
	}

	protected void sort(List<GTreeNode> list) {
		Collections.sort(list, getChildrenComparator());
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean isCut() {
		return isCut;
	}

	@Override
	public boolean isEditable() {
		return true;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		this.isCut = isCut;
		fireNodeChanged();
	}

	@Override
	public Symbol getSymbol() {
		return symbol;
	}

	public long getSymbolID() {
		return symbol.getID();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return symbol.getName();
	}

	@Override
	public String getDisplayText() {
		if (cachedDisplayName == null) {
			cachedDisplayName = computeDisplayName(getName());
		}
		return cachedDisplayName;
	}

	private String computeDisplayName(String baseName) {
		if (symbol.isExternal()) {
			ExternalLocation external =
				symbol.getProgram().getExternalManager().getExternalLocation(symbol);
			if (external != null) {
				String originalImportedName = external.getOriginalImportedName();
				if (originalImportedName != null) {
					return baseName + " / " + originalImportedName;
				}
			}
		}
		return baseName;
	}

	// for editing
	@Override
	public String toString() {
		return getName();
	}

	@Override
	public String getToolTip() {
		return "<html>" + HTMLUtilities.escapeHTML(symbol.getName(true));
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return null;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}

	@Override
	public Namespace getNamespace() {
		return null;
	}

	protected void doInsertNode(GTreeNode newNode) {

		Comparator<GTreeNode> comparator = getChildrenComparator();
		List<GTreeNode> children = getChildren();
		int index = Collections.binarySearch(children, newNode, comparator);
		if (index >= 0) { // already a child			
			return;
		}

		index = -index - 1;
		addNode(index, newNode);
	}

	public static SymbolNode createNode(Symbol symbol, Program program) {

		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType.equals(SymbolType.CLASS)) {
			return new ClassSymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.LABEL)) {
			return new CodeSymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.FUNCTION)) {
			return new FunctionSymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.LIBRARY)) {
			return new LibrarySymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.LOCAL_VAR)) {
			return new LocalVariableSymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.NAMESPACE)) {
			return new NamespaceSymbolNode(program, symbol);
		}
		else if (symbolType.equals(SymbolType.PARAMETER)) {
			return new ParameterSymbolNode(program, symbol);
		}

		// default
		return new SymbolNode(program, symbol);
	}

	@Override
	public void valueChanged(Object newValue) {
		// since we allow a symbol rename to optionally include full namespace path
		if (symbol.getName().equals(newValue) || symbol.getName(true).equals(newValue)) {
			return;
		}

		SymbolPath symbolPath = new SymbolPath((String) newValue);
		String namespacePath = symbolPath.getParentPath();
		if (namespacePath == null) {
			namespacePath = GlobalNamespace.GLOBAL_NAMESPACE_NAME;
		}

		int transactionID = program.startTransaction("Rename Symbol");
		try {
			// The symbol node rename does not support moving symbols into the
			// Global space since this implies a simple rename
			Namespace namespace = createNewNamespace(symbolPath.getParent());
			if (!namespace.isGlobal()) {
				symbol.setNameAndNamespace(symbolPath.getName(), namespace,
					SourceType.USER_DEFINED);
			}
			else {
				symbol.setName(symbolPath.getName(), SourceType.USER_DEFINED);
			}
		}
		catch (DuplicateNameException exc) {
			Msg.showError(getClass(), null, "Rename Failed", "Symbol by the name " +
				symbolPath.getName() + " already exists in namespace: " + namespacePath + ".");
		}
		catch (InvalidInputException exc) {
			String msg = exc.getMessage();
			if (msg == null) {
				msg = "Invalid name specified: " + newValue;
			}
			Msg.showError(getClass(), null, "Invalid Name Specified", exc.getMessage());
		}
		catch (CircularDependencyException e) {
			Msg.showError(getClass(), null, "Rename Failed", "Unable to create the symbol \"" +
				symbolPath.getName() + "\" under namespace " + namespacePath);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private Namespace createNewNamespace(SymbolPath namespacePath) throws InvalidInputException {
		if (namespacePath == null) {
			return program.getGlobalNamespace();
		}
		CreateNamespacesCmd cmd =
			new CreateNamespacesCmd(namespacePath.getPath(), SourceType.USER_DEFINED);
		if (!cmd.applyTo(program)) {
			throw new InvalidInputException(cmd.getStatusMsg());
		}
		return cmd.getNamespace();
	}

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

		SymbolNode node = (SymbolNode) o;
		if (symbol != null) {
			boolean symbolEquals = symbol.equals(node.symbol);
			return symbolEquals;
		}
		boolean nameEquals = getName().equals(node.getName());
		return nameEquals;
	}

	// overridden to handle duplicate symbols
	@Override
	public int compareTo(GTreeNode node) {
		String dt1 = getDisplayText();
		String dt2 = node.getDisplayText();

		int nameCompare = AlphaNumericComparator.CI.compare(dt1, dt2);
		if (nameCompare != 0) {
			return nameCompare;
		}

		// next, use case sensitive to tie-break
		nameCompare = AlphaNumericComparator.CS.compare(dt1, dt2);
		if (nameCompare != 0) {
			return -nameCompare; // negate the result so that lower comes first
		}

		if (node instanceof SymbolNode other) {
			// when two symbol nodes have exactly the same name, use a tie-breaker
			return SYMBOL_COMPARATOR.compare(symbol, other.symbol);
		}

		return 0;
	}
}
