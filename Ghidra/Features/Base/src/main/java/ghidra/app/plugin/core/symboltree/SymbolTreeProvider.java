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
package ghidra.app.plugin.core.symboltree;

import java.awt.BorderLayout;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeNodeTransferable;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.tasks.GTreeBulkTask;
import ghidra.app.plugin.core.symboltree.actions.*;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class SymbolTreeProvider extends ComponentProviderAdapter {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/sitemap_color.png");
	private final static String NAME = "Symbol Tree";

	private ClipboardOwner clipboardOwner;
	private Clipboard localClipboard;// temporary clipboard used for the "cut" operation

	private DomainObjectListener domainObjectListener;
	private Program program;

	private final SymbolTreePlugin plugin;
	private SymbolGTree tree;
	private JPanel mainPanel;
	private JComponent component;

	private GoToToggleAction goToToggleAction;

	/**
	 * A list into which tasks to be run will accumulated until we put them into the GTree's
	 * task system.  We do this because the tasks run so fast that we can get too much thread
	 * creation from the GTree's worker.  By buffering these behind a SwingUpdateManager, we will
	 * prevent to much work from happening too fast.  Also, we perform the work in a bulk task
	 * so that the tree can benefit from optimizations made by the bulk task.
	 */
	private List<GTreeTask> bufferedTasks = new ArrayList<>();
	private SwingUpdateManager domainChangeUpdateManager = new SwingUpdateManager(1000,
		SwingUpdateManager.DEFAULT_MAX_DELAY, "Symbol Tree Provider", () -> {

			if (bufferedTasks.isEmpty()) {
				return;
			}

			if (bufferedTasks.size() == 1) {
				//
				// Single events happen from user operations, like creating namespaces and
				// rename operations.
				//
				// Perform a simple update in the normal fashion (a single, targeted filter
				// performed when adding changing one symbol is faster than the complete
				// refilter done by the bulk task below).
				//
				tree.runTask(bufferedTasks.remove(0));
				return;
			}

			ArrayList<GTreeTask> copiedTasks = new ArrayList<>(bufferedTasks);
			bufferedTasks.clear();
			tree.runTask(new BulkWorkTask(tree, copiedTasks));
		});

	private Map<Program, GTreeState> treeStateMap = new HashMap<>();

	public SymbolTreeProvider(PluginTool tool, SymbolTreePlugin plugin) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();

		domainObjectListener = new SymbolTreeProviderDomainObjectListener();

		localClipboard = new Clipboard(NAME);

		component = buildProvider();
		plugin.getTool().addComponentProvider(this, false);

		createActions();

		setHelpLocation(new HelpLocation("SymbolTreePlugin", "Symbol_Tree"));
	}

//==================================================================================================
// Setup Methods
//==================================================================================================

	private JComponent buildProvider() {
		mainPanel = new JPanel(new BorderLayout());

		tree = createTree(new SymbolTreeRootNode());
		mainPanel.add(tree, BorderLayout.CENTER);

		// There's no reason to see the root node in this window. The name (GLOBAL) is
		// unimportant and the tree is never collapsed at this level.
		tree.setRootVisible(false);

		return mainPanel;
	}

	private SymbolGTree createTree(SymbolTreeRootNode rootNode) {
		if (tree != null) {
			GTreeNode oldRootNode = tree.getModelRoot();
			tree.setProgram(rootNode.getProgram());
			tree.setRootNode(rootNode);

			oldRootNode.removeAll();// assist in cleanup a bit
			return tree;
		}

		SymbolGTree newTree = new SymbolGTree(rootNode, plugin);

		newTree.addGTreeSelectionListener(e -> {

			EventOrigin origin = e.getEventOrigin();
			if (origin != EventOrigin.USER_GENERATED) {
				contextChanged();
				return;
			}

			maybeGoToSymbol();
			contextChanged();
		});

		newTree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

				// This code serves to perform navigation in  the case that the selection handler
				// above does not, as is the case when the node is already selected.  This code 
				// will get called on the mouse release, whereas the selection handler gets called
				// on the mouse pressed.
				// For now, just attempt to perform the goto.  It may get called twice, but this
				// should have no real impact on performance.

				maybeGoToSymbol();
			}
		});

		newTree.addTreeExpansionListener(new TreeExpansionListener() {

			@Override
			public void treeExpanded(TreeExpansionEvent event) {
				// nothing
			}

			@Override
			public void treeCollapsed(TreeExpansionEvent event) {
				treeNodeCollapsed(event.getPath());
			}
		});

		newTree.setEditable(true);

		return newTree;
	}

	protected void treeNodeCollapsed(TreePath path) {
		Object lastPathComponent = path.getLastPathComponent();
		if (lastPathComponent instanceof SymbolCategoryNode) {
			tree.runTask(m -> ((SymbolCategoryNode) lastPathComponent).unloadChildren());
		}
	}

	private void maybeGoToSymbol() {

		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null || paths.length != 1) {
			return;
		}

		Object object = paths[0].getLastPathComponent();
		if (!(object instanceof SymbolNode)) {
			return;
		}

		SymbolNode node = (SymbolNode) object;
		Symbol symbol = node.getSymbol();
		SymbolType type = symbol.getSymbolType();
		if (!type.isNamespace() || type == SymbolType.FUNCTION) {
			plugin.goTo(symbol);
		}
	}

	private void createActions() {
		DockingAction createImportAction = new CreateLibraryAction(plugin);
		DockingAction setExternalProgramAction = new SetExternalProgramAction(plugin, this);
		DockingAction createExternalLocationAction = new CreateExternalLocationAction(plugin);
		DockingAction editExternalLocationAction = new EditExternalLocationAction(plugin);

		String createGroup = "0Create";
		int createGroupIndex = 0;
		DockingAction createNamespaceAction = new CreateNamespaceAction(plugin, createGroup,
			Integer.toString(createGroupIndex++));
		DockingAction createClassAction = new CreateClassAction(plugin, createGroup,
			Integer.toString(createGroupIndex++));
		DockingAction convertToClassAction = new ConvertToClassAction(plugin, createGroup,
			Integer.toString(createGroupIndex++));

		DockingAction renameAction = new RenameAction(plugin);
		DockingAction cutAction = new CutAction(plugin, this);
		DockingAction pasteAction = new PasteAction(plugin, this);
		DockingAction deleteAction = new DeleteAction(plugin);
		deleteAction.setEnabled(false);

		DockingAction referencesAction =
			new ShowSymbolReferencesAction(plugin.getTool(), plugin.getName());

		DockingAction selectionAction = new SelectionAction(plugin);
		selectionAction.setEnabled(false);

		goToToggleAction = new GoToToggleAction(plugin);
		DockingAction goToExternalAction = new GoToExternalLocationAction(plugin);
		goToExternalAction.setEnabled(false);

		tool.addLocalAction(this, createImportAction);
		tool.addLocalAction(this, setExternalProgramAction);
		tool.addLocalAction(this, createExternalLocationAction);
		tool.addLocalAction(this, editExternalLocationAction);
		tool.addLocalAction(this, createClassAction);
		tool.addLocalAction(this, createNamespaceAction);
		tool.addLocalAction(this, convertToClassAction);
		tool.addLocalAction(this, renameAction);
		tool.addLocalAction(this, cutAction);
		tool.addLocalAction(this, pasteAction);
		tool.addLocalAction(this, deleteAction);
		tool.addLocalAction(this, referencesAction);
		tool.addLocalAction(this, goToToggleAction);
		tool.addLocalAction(this, selectionAction);
		tool.addLocalAction(this, goToExternalAction);
	}

//==================================================================================================
// ComponentProvider Methods
//==================================================================================================

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		return new SymbolTreeActionContext(this, program, tree, tree.getSelectionPaths());
	}

	@Override
	public void componentShown() {
		setProgram(program);
	}

//==================================================================================================
// Class Methods
//==================================================================================================

	void programActivated(Program openedProgram) {
		this.program = openedProgram;
		if (tool.isVisible(this)) {
			setProgram(openedProgram);
		}
	}

	private void setProgram(Program program) {
		if (program == null) {
			return;
		}

		program.addListener(domainObjectListener);

		mainPanel.remove(tree);
		tree = createTree(new SymbolTreeRootNode(program));
		mainPanel.add(tree);
		component.validate();

		// restore any state that may be saved
		GTreeState treeState = treeStateMap.get(program);
		if (treeState != null) {
			tree.restoreTreeState(treeState);
		}
	}

	void programDeactivated(Program deactivatedProgram) {
		tree.cancelWork();

		deactivatedProgram.removeListener(domainObjectListener);

		// see if the user has a tree state (opened/selected nodes) and save it
		GTreeState treeState = tree.getTreeState();
		treeStateMap.put(program, treeState);

		mainPanel.remove(tree);
		tree = createTree(new SymbolTreeRootNode());
		mainPanel.add(tree);
		component.validate();
		this.program = null;
	}

	void programClosed(Program closedProgram) {
		treeStateMap.remove(closedProgram);
	}

	public void setClipboardContents(GTreeNodeTransferable symbolTreeNodeTransferable) {
		localClipboard.setContents(symbolTreeNodeTransferable, clipboardOwner);
	}

	public Clipboard getClipboard() {
		return localClipboard;
	}

	public int reparentSymbols(Namespace namespace, List<Symbol> symbolList) {
		int count = 0;
		StringBuffer sb = new StringBuffer();
		int transactionID = program.startTransaction("Change Parent Namespaces");
		try {
			for (Symbol symbol : symbolList) {

				if (!canReparentSymbol(symbol) || !canMoveSymbol(namespace, symbol)) {
					continue;
				}

				try {
					symbol.setNamespace(namespace);
					++count;
				}
				catch (DuplicateNameException e) {
					sb.append("Parent namespace " + namespace.getName() +
						" contains namespace named " + symbol.getName() + "\n");
				}
				catch (InvalidInputException | CircularDependencyException e) {
					sb.append("Could not change parent namespace for " + symbol.getName() + ": " +
						e.getMessage() + "\n");
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		if (sb.length() > 0) {
			Msg.showInfo(getClass(), null, "Change Parent Namespace Failed", sb.toString());
		}
		return count;
	}

	private boolean canMoveSymbol(Namespace destinationNamespace, Symbol symbol) {
		SymbolTable symbolTable = program.getSymbolTable();

		if (symbol.isDescendant(destinationNamespace)) {
			return false;
		}
		if (!symbol.isValidParent(destinationNamespace)) {
			return false;
		}
		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType.allowsDuplicates()) {
			return true;
		}
		// the symbol to move does not allow dups, so make sure all existing symbols do allow dups.
		List<Symbol> symbols = symbolTable.getSymbols(symbol.getName(), destinationNamespace);
		for (Symbol s : symbols) {
			if (!s.getSymbolType().allowsDuplicates()) {
				return false;
			}
		}
		return true;
	}

	private boolean canReparentSymbol(Symbol symbol) {
		SymbolType symbolType = symbol.getSymbolType();
		return (symbolType == SymbolType.LABEL) || (symbolType == SymbolType.FUNCTION) ||
			(symbolType == SymbolType.NAMESPACE) || (symbolType == SymbolType.CLASS);
	}

	private void rebuildTree() {
		SymbolTreeRootNode node = (SymbolTreeRootNode) tree.getModelRoot();
		node.setChildren(null);
		tree.refilterLater();
	}

	private void symbolChanged(Symbol symbol, String oldName) {
		addTask(new SymbolChangedTask(tree, symbol, oldName));
	}

	private void symbolAdded(Symbol symbol) {
		addTask(new SymbolAddedTask(tree, symbol));
	}

	private void symbolRemoved(Symbol symbol) {
		addTask(new SymbolRemovedTask(tree, symbol));
	}

	private void addTask(GTreeTask task) {
		// Note: if we want to call this method from off the Swing thread, then we have to
		//       synchronize on the list that we are adding to here.
		Swing.assertSwingThread(
			"Adding tasks must be done on the Swing thread," +
				"since they are put into a list that is processed on the Swing thread. ");

		bufferedTasks.add(task);
		domainChangeUpdateManager.update();
	}

	void showComponent(Program currentProgram) {
		if (!tool.isVisible(this)) {
			setProgram(currentProgram);
		}
		tool.showComponentProvider(this, true);
	}

	public void locationChanged(ProgramLocation loc) {
		if (!goToToggleAction.isSelected()) {
			return;
		}

		Symbol symbol = null;
		Address addr = loc.getAddress();
		if (loc instanceof VariableLocation) {
			Variable var = ((VariableLocation) loc).getVariable();
			if (var == null) {
				return;
			}
			symbol = var.getSymbol();
		}
		else if ((loc instanceof FunctionSignatureFieldLocation) ||
			(loc instanceof FunctionReturnTypeFieldLocation)) {
			Function function = program.getFunctionManager().getFunctionContaining(addr);
			if (function == null) {
				return;
			}
			symbol = function.getSymbol();
		}
		else if (loc instanceof OperandFieldLocation) {
			// look for local variable in the operand field
			int opIndex = ((OperandFieldLocation) loc).getOperandIndex();
			CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
			Reference[] refs = cu.getOperandReferences(opIndex);
			for (Reference element : refs) {
				symbol = program.getSymbolTable().getSymbol(element);
				if (symbol != null) {
					break;
				}
			}
		}
		else if (loc instanceof LabelFieldLocation) {
			LabelFieldLocation lfLoc = (LabelFieldLocation) loc;
			symbol = lfLoc.getSymbol();
		}
		else {
			symbol = program.getSymbolTable().getPrimarySymbol(loc.getAddress());
		}

		if (symbol == null || symbol.isDynamic()) {
			return;
		}

		SymbolTreeRootNode rootNode = (SymbolTreeRootNode) tree.getViewRoot();
		tree.runTask(new SearchTask(tree, rootNode, symbol));
	}

	void readConfigState(SaveState saveState) {
		goToToggleAction.setSelected(saveState.getBoolean("GO_TO_TOGGLE_STATE", false));
	}

	void writeConfigState(SaveState saveState) {
		saveState.putBoolean("GO_TO_TOGGLE_STATE", goToToggleAction.isSelected());
	}

	void dispose() {

		domainChangeUpdateManager.dispose();
		bufferedTasks.clear();
		tree.dispose();

		treeStateMap.clear();
		tree = null;

		mainPanel.removeAll();

		if (program != null) {
			program.removeListener(domainObjectListener);
			program = null;
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SearchTask extends GTreeTask {

		private SymbolTreeRootNode rootNode;
		private Symbol searchSymbol;

		private SearchTask(GTree tree, SymbolTreeRootNode rootNode, Symbol searchSymbol) {
			super(tree);
			this.rootNode = rootNode;
			this.searchSymbol = searchSymbol;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			monitor.setMessage("Searching for " + searchSymbol.getName());
			SymbolNode key = SymbolNode.createNode(searchSymbol, program);
			GTreeNode node = rootNode.findSymbolTreeNode(key, true, monitor);
			if (node != null) {
				tree.setSelectedNode(node);
			}
		}
	}

	private abstract class AbstactSymbolUpdateTask extends GTreeTask {

		protected final Symbol symbol;

		AbstactSymbolUpdateTask(GTree tree, Symbol symbol) {
			super(tree);
			this.symbol = symbol;
		}

		abstract void doRun(TaskMonitor monitor) throws CancelledException;

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			TreePath[] selectionPaths = tree.getSelectionPaths();
			doRun(monitor);

			if (selectionPaths.length != 0) {
				tree.setSelectionPaths(selectionPaths);
			}
		}

		@Override
		public String toString() {
			return getClass().getSimpleName() + " " + symbol;
		}
	}

	private class SymbolAddedTask extends AbstactSymbolUpdateTask {

		SymbolAddedTask(GTree tree, Symbol symbol) {
			super(tree, symbol);
		}

		@Override
		void doRun(TaskMonitor monitor) throws CancelledException {

			SymbolTreeRootNode rootNode = (SymbolTreeRootNode) tree.getModelRoot();

			// the symbol may have been deleted while we are processing bulk changes
			if (!symbol.isDeleted()) {
				GTreeNode newNode = rootNode.symbolAdded(symbol);
				tree.refilterLater(newNode);
			}
		}
	}

	private class SymbolChangedTask extends AbstactSymbolUpdateTask {

		private String oldName;

		SymbolChangedTask(GTree tree, Symbol symbol, String oldName) {
			super(tree, symbol);
			this.oldName = oldName;
		}

		@Override
		void doRun(TaskMonitor monitor) throws CancelledException {

			SymbolTreeRootNode root = (SymbolTreeRootNode) tree.getModelRoot();
			root.symbolRemoved(symbol, oldName, monitor);

			// the symbol may have been deleted while we are processing bulk changes
			if (!symbol.isDeleted()) {
				root.symbolAdded(symbol);
			}
			tree.refilterLater();
		}
	}

	private class SymbolRemovedTask extends AbstactSymbolUpdateTask {

		SymbolRemovedTask(GTree tree, Symbol symbol) {
			super(tree, symbol);
		}

		@Override
		void doRun(TaskMonitor monitor) throws CancelledException {
			SymbolTreeRootNode root = (SymbolTreeRootNode) tree.getModelRoot();
			root.symbolRemoved(symbol, monitor);
			tree.refilterLater();
		}
	}

	private class BulkWorkTask extends GTreeBulkTask {

		// somewhat arbitrary max amount of work to perform...at some point it is faster to
		// just reload the tree
		private static final int MAX_TASK_COUNT = 1000;

		private List<GTreeTask> tasks;

		BulkWorkTask(GTree gTree, List<GTreeTask> tasks) {
			super(gTree);
			this.tasks = tasks;
		}

		@Override
		public void runBulk(TaskMonitor monitor) throws CancelledException {

			if (tasks.size() > MAX_TASK_COUNT) {
				Swing.runLater(() -> rebuildTree());
				return;
			}

			for (GTreeTask task : tasks) {
				monitor.checkCanceled();
				task.run(monitor);
			}
		}
	}

	private class SymbolTreeProviderDomainObjectListener implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent event) {

			if (ignoreEvents()) {
				return;
			}

			if (event.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
				rebuildTree();
				return;
			}

			int recordCount = event.numRecords();
			for (int i = 0; i < recordCount; i++) {
				DomainObjectChangeRecord rec = event.getChangeRecord(i);
				int eventType = rec.getEventType();

				Object object = null;
				if (rec instanceof ProgramChangeRecord) {
					object = ((ProgramChangeRecord) rec).getObject();
				}

				if (eventType == ChangeManager.DOCR_SYMBOL_RENAMED) {
					Symbol symbol = (Symbol) object;
					symbolChanged(symbol, (String) rec.getOldValue());
				}
				else if (eventType == ChangeManager.DOCR_SYMBOL_DATA_CHANGED ||
					eventType == ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED ||
					eventType == ChangeManager.DOCR_FUNCTION_CHANGED) {

					Symbol symbol = null;
					if (object instanceof Symbol) {
						symbol = (Symbol) object;
					}
					else if (object instanceof Namespace) {
						symbol = ((Namespace) object).getSymbol();
					}

					symbolChanged(symbol, symbol.getName());
				}
				else if (eventType == ChangeManager.DOCR_SYMBOL_ADDED) {
					Symbol symbol = (Symbol) rec.getNewValue();
					symbolAdded(symbol);
				}
				else if (eventType == ChangeManager.DOCR_SYMBOL_REMOVED) {
					Symbol symbol = (Symbol) object;
					symbolRemoved(symbol);
				}
				else if (eventType == ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_ADDED ||
					eventType == ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_REMOVED) {
					ProgramChangeRecord programChangeRecord = (ProgramChangeRecord) rec;
					Address address = programChangeRecord.getStart();
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol[] symbols = symbolTable.getSymbols(address);
					for (Symbol symbol : symbols) {
						symbolChanged(symbol, symbol.getName());
					}
				}
			}

		}

		private boolean ignoreEvents() {
			if (!isVisible()) {
				return true;
			}
			return treeIsCollapsed();
		}

		private boolean treeIsCollapsed() {
			// note: the root's children are visible by default
			GTreeNode root = tree.getViewRoot();
			if (!root.isExpanded()) {
				return true;
			}
			List<GTreeNode> children = root.getChildren();
			for (GTreeNode node : children) {
				if (node.isExpanded()) {
					return false;
				}
			}
			return true;
		}
	}
}
