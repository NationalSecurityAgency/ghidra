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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Special type of Namespace node just for the imports category. This one is special in that it
 * only includes symbols from the library that it is within or child namespaces that contain
 * external symbols from the library this node is within.
 */
public class ImportsNamespaceNode extends SymbolNode {
	private static final Icon NAMESPACE_ICON = NamespaceSymbolNode.NAMESPACE_ICON;
	private static final Icon DISABLED_NAMESPACE_ICON = NamespaceSymbolNode.DISABLED_NAMESPACE_ICON;

	private Set<Symbol> symbols;
	private Namespace namespace;

	public ImportsNamespaceNode(Namespace namespace, Symbol s, Program program) {
		// make sure the set is mutable
		this(namespace, new HashSet<>(Set.of(s)), program);
	}

	public ImportsNamespaceNode(Namespace namespace, Set<Symbol> set, Program program) {
		super(program, namespace.getSymbol());
		this.symbols = new HashSet<>(set);  // the set must be mutable
		this.namespace = namespace;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return DISABLED_NAMESPACE_ICON;
		}
		return NAMESPACE_ICON;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return NAMESPACE_DATA_FLAVOR;
	}

	@Override
	public Namespace getNamespace() {
		return namespace;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) {
		List<GTreeNode> list = new ArrayList<>();
		Map<Namespace, Set<Symbol>> map = organizeByNamespace(symbols, namespace);
		Set<Symbol> directChildren = map.computeIfAbsent(namespace, k -> new HashSet<Symbol>());
		for (Symbol s : directChildren) {
			list.add(createNode(s, program));
		}
		map.remove(namespace);
		for (Namespace ns : map.keySet()) {
			list.add(new ImportsNamespaceNode(ns, map.get(ns), program));
		}
		sort(list);
		return list;
	}

	static Map<Namespace, Set<Symbol>> organizeByNamespace(Set<Symbol> symbols,
			Namespace root) {
		Map<Namespace, Set<Symbol>> map = new HashMap<>();
		for (Symbol s : symbols) {
			Namespace topNamespace = getTopLevelNamespace(s, root);
			Set<Symbol> list = map.computeIfAbsent(topNamespace, k -> new HashSet<Symbol>());
			list.add(s);
		}
		return map;
	}

	static Namespace getTopLevelNamespace(Symbol s, Namespace root) {
		Namespace parentNamespace = s.getParentNamespace();
		if (parentNamespace == root) {
			return root;
		}
		while (parentNamespace.getParentNamespace() != root) {
			parentNamespace = parentNamespace.getParentNamespace();
		}
		return parentNamespace;
	}

	public SymbolNode symbolAdded(Symbol s) {
		symbols.add(s);
		if (!isLoaded()) {
			return null;
		}
		Namespace topNamespace = getTopLevelNamespace(s, namespace);
		if (topNamespace == namespace) {
			SymbolNode node = createNode(s, program);
			doInsertNode(node);
			return node;
		}
		GTreeNode child = getChild(topNamespace.getName());
		if (child instanceof ImportsNamespaceNode namespaceNode) {
			return namespaceNode.symbolAdded(s);
		}
		doInsertNode(new ImportsNamespaceNode(topNamespace, symbol, program));

		// The direct parent namespace node of the symbol is not in the tree. We did add one of
		// its ancestors above, but did not add the symbol itself.
		return null;
	}

	void removeSymbol(Symbol s) {
		symbols.remove(s);
		if (symbols.isEmpty()) {
			getParent().removeNode(this);
		}
	}
}
