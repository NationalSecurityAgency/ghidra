package ghidra.app.plugin.core.debug.gui.model;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeState;

public class KeepTreeState implements AutoCloseable {
	private final GTree tree;
	private final GTreeState state;

	public static KeepTreeState ifNotNull(GTree tree) {
		if (tree == null) {
			return null;
		}
		return new KeepTreeState(tree);
	}

	public KeepTreeState(GTree tree) {
		this.tree = tree;
		this.state = tree.getTreeState();
	}

	@Override
	public void close() {
		tree.restoreTreeState(state);
	}
}