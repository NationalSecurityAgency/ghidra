package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.tree.TreePath;

import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;

/**
 * Symbol tree action for converting a namespace to a class
 */
public class ConvertToClassAction extends SymbolTreeContextAction {

	private static final String NAME = "Convert To Class";

	public ConvertToClassAction(SymbolTreePlugin plugin) {
		super(NAME, plugin.getName());
		setPopupMenuData(new MenuData(new String[] { NAME }, "1Convert"));
		setEnabled(false);
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		Object object = selectionPaths[0].getLastPathComponent();
		if (object instanceof SymbolNode) {
			SymbolNode symbolNode = (SymbolNode) object;
			Symbol symbol = symbolNode.getSymbol();
			return symbol.getSymbolType() == SymbolType.NAMESPACE;
		}
		return false;
	}

	@Override
	protected void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();

		Program program = context.getProgram();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();

		Symbol symbol = ((SymbolNode) node).getSymbol();
		Namespace parent = (Namespace) symbol.getObject();
		if (parent != null) {
			convertToClass(program, parent);
			program.flushEvents();
			context.getSymbolTree().startEditing(node, parent.getName());
		}
	}

	private static void convertToClass(Program program, Namespace ns) {
		int id = program.startTransaction(NAME);
		boolean success = false;
		try {
			NamespaceUtils.convertNamespaceToClass(ns);
			success = true;
		} catch (InvalidInputException e) {
			// This is thrown when the provided namespace is a function
			// It was checked in isEnabledForContext and thus cannot occur
			throw new AssertException(e);
		} finally {
			program.endTransaction(id, success);
		}
	}

}
