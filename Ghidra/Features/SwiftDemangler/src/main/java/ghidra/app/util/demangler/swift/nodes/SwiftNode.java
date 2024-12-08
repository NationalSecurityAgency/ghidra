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
package ghidra.app.util.demangler.swift.nodes;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;
import ghidra.app.util.demangler.swift.nodes.generic.*;

/**
 * A single Swift demangled symbol tree node
 */
public abstract class SwiftNode {

	protected NodeProperties properties;
	private SwiftNode parent;
	private List<SwiftNode> children = new ArrayList<>();
	private boolean childSkipped = false;

	/**
	 * Represents {@link SwiftNode} properties
	 * 
	 * @param kind The {@link SwiftDemangledNodeKind kind} of {@link SwiftNode}
	 * @param text The text attribute, or null if it does not exist
	 * @param index The index attribute, or null if it does not exist
	 * @param depth The depth of the {@link SwiftNode} in the demangled symbol tree (root depth is 
	 *   0)
	 * @param mangled The mangled string associated with this {@link SwiftNode}
	 * @param originalDemangled The natively demangled string
	 */
	public record NodeProperties(SwiftDemangledNodeKind kind, String text, String index,
			int depth, String mangled, String originalDemangled) {}

	/**
	 * Gets a new {@link SwiftNode} with the given with the given {@link NodeProperties}
	 * 
	 * @param props The {@link NodeProperties}
	 * @return A {@link SwiftNode} with the given {@link NodeProperties}
	 */
	public static SwiftNode get(NodeProperties props) {
		SwiftNode node = switch (props.kind()) {
			case Allocator -> new SwiftAllocatorNode();
			case AnonymousDescriptor -> new SwiftGenericDescriptorNode();
			case ArgumentTuple -> new SwiftGenericPassthroughNode();
			case BoundGenericStructure -> new SwiftBoundGenericStructureNode();
			case BuiltinTypeName -> new SwiftBuiltinTypeNameNode();
			case Class -> new SwiftClassNode();
			case Constructor -> new SwiftConstructorNode();
			case Deallocator -> new SwiftDeallocatorNode();
			case DefaultArgumentInitializer -> new SwiftGenericPassthroughNode();
			case DependentGenericParamType -> new SwiftDependentGenericParamTypeNode();
			case DependentGenericType -> new SwiftDependentGenericTypeNode();
			case Destructor -> new SwiftDestructorNode();
			case DispatchThunk -> new SwiftGenericPassthroughNode();
			case Enum -> new SwiftEnumNode();
			case Extension -> new ghidra.app.util.demangler.swift.nodes.SwiftExtensionNode();
			case Function -> new SwiftFunctionNode();
			case FunctionType -> new SwiftFunctionTypeNode();
			case GenericSpecialization -> new SwiftGenericTextNode();
			case Getter -> new SwiftGetterNode();
			case Global -> new SwiftGlobalNode();
			case GlobalVariableOnceDeclList -> new SwiftGlobalVariableOnceDeclListNode();
			case GlobalVariableOnceFunction -> new SwiftGlobalVariableOnceFunctionNode();
			case Identifier -> new SwiftGenericTextNode();
			case InfixOperator -> new SwiftGenericTextNode();
			case Initializer -> new SwiftInitializerNode();
			case InOut -> new SwiftInOutNode();
			case LabelList -> new SwiftLabelListNode();
			case LazyProtocolWitnessTableAccessor -> new SwiftLazyProtocolWitnessTableAccessorNode();
			case LocalDeclName -> new SwiftLocalDeclNameNode();
			case MergedFunction -> new SwiftGenericPassthroughNode();
			case ModifyAccessor -> new SwiftModifyAccessorNode();
			case Module -> new SwiftGenericTextNode();
			case ModuleDescriptor -> new SwiftGenericDescriptorNode();
			case NominalTypeDescriptor -> new SwiftGenericDescriptorNode();
			case Number -> new SwiftGenericIndexNode();
			case ObjCAttribute -> new SwiftGenericTextNode();
			case OutlinedConsume -> new SwiftOutlinedConsumeNode();
			case OutlinedCopy -> new SwiftOutlinedCopyNode();
			case Owned -> new SwiftGenericPassthroughNode();
			case PrivateDeclName -> new SwiftPrivateDeclNameNode();
			case Protocol -> new SwiftProtocolNode();
			case ProtocolConformance -> new SwiftProtocolConformanceNode();
			case ProtocolConformanceDescriptor -> new SwiftGenericDescriptorNode();
			case ProtocolDescriptor -> new SwiftGenericDescriptorNode();
			case ProtocolWitness -> new SwiftGenericPassthroughNode();
			case ReflectionMetadataBuiltinDescriptor -> new SwiftGenericDescriptorNode();
			case ReflectionMetadataFieldDescriptor -> new SwiftGenericDescriptorNode();
			case ReturnType -> new SwiftGenericPassthroughNode();
			case Setter -> new SwiftSetterNode();
			case Static -> new SwiftGenericPassthroughNode();
			case Structure -> new SwiftStructureNode();
			case Subscript -> new SwiftSubscriptNode();
			case Suffix -> new SwiftGenericTextNode();
			case Tuple -> new SwiftTupleNode();
			case TupleElement -> new SwiftTupleElementNode();
			case TupleElementName -> new SwiftGenericTextNode();
			case Type -> new SwiftGenericPassthroughNode();
			case TypeAlias -> new SwiftTypeAliasNode();
			case TypeList -> new SwiftTypeListNode();
			case TypeMetadataAccessFunction -> new SwiftTypeMetadataAccessFunctionNode();
			case UnsafeMutableAddressor -> new SwiftUnsafeMutableAddressorNode();
			case Variable -> new SwiftVariableNode();
			default -> new SwiftUnsupportedNode(props.kind().toString(), props);
		};
		node.properties = props;
		return node;
	}

	/**
	 * Demangles this {@link SwiftNode}
	 * 
	 * @param demangler The {@link SwiftDemangler}
	 * @return The demangled {@link SwiftNode}
	 * @throws DemangledException if a problem occurred
	 */
	public abstract Demangled demangle(SwiftDemangler demangler)
			throws DemangledException;

	/**
	 * Gets the {@link SwiftDemangledNodeKind kind} of {@link SwiftNode}
	 * 
	 * @return The {@link SwiftDemangledNodeKind kind} of {@link SwiftNode}
	 */
	public SwiftDemangledNodeKind getKind() {
		return properties.kind();
	}

	/**
	 * Gets the "text" property
	 * 
	 * @return The "text" attribute, or null if it does not exist
	 */
	public String getText() {
		return properties.text();
	}

	/**
	 * Gets the "index" property
	 * 
	 * @return The "index" attribute, or null if it does not exist
	 */
	public String getIndex() {
		return properties.index();
	}

	/**
	 * Gets the depth of the {@link SwiftNode} in the demangled symbol tree (root depth is 0)
	 * 
	 * @return The depth of the {@link SwiftNode} in the demangled symbol tree (root depth is 0)
	 */
	public int getDepth() {
		return properties.depth();
	}

	/**
	 * Gets the parent {@link SwiftNode}
	 * 
	 * @return The parent {@link SwiftNode}, or null if this is the root {@link SwiftNode}
	 */
	public SwiftNode getParent() {
		return parent;
	}

	/**
	 * Sets the parent {@link SwiftNode}
	 * 
	 * @param parent The parent {@link SwiftNode}
	 */
	public void setParent(SwiftNode parent) {
		this.parent = parent;
	}

	/**
	 * Gets the {@link List} of child {@link SwiftNode}s
	 * 
	 * @return The {@link List} of child {@link SwiftNode} (original, not a copy)
	 */
	public List<SwiftNode> getChildren() {
		return children;
	}

	/**
	 * Walks down the tree rooted at this {@link SwiftNode}, returning true if the given condition 
	 * is met on any {@link SwiftNode} encountered
	 * 
	 * @param predicate The condition to test for
	 * @return True if the given condition is true on any {@link SwiftNode} encountered; otherwise, 
	 *   false
	 */
	public boolean walkAndTest(Predicate<SwiftNode> predicate) {
		if (predicate.test(this)) {
			return true;
		}
		for (SwiftNode child : children) {
			if (child.walkAndTest(predicate)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks to see if the {@link SwiftNode} has any direct children of the given 
	 * {@link SwiftDemangledNodeKind kind}
	 * 
	 * @param childKind The {@link SwiftDemangledNodeKind kind} of child to check for
	 * @return True if the {@link SwiftNode} has any direct children of the given 
	 *   {@link SwiftDemangledNodeKind kind}; otherwise false
	 */
	public boolean hasChild(SwiftDemangledNodeKind childKind) {
		return children.stream().anyMatch(child -> child.getKind().equals(childKind));
	}

	/**
	 * Gets the first direct child {@link SwiftNode} of the given 
	 * {@link SwiftDemangledNodeKind kind}
	 * 
	 * @param childKind The {@link SwiftDemangledNodeKind kind} of child to get
	 * @return The first direct child {@link SwiftNode} of the given 
	 *   {@link SwiftDemangledNodeKind kind}, or null if one could not be found
	 */
	public SwiftNode getChild(SwiftDemangledNodeKind childKind) {
		return children.stream()
				.filter(child -> child.getKind().equals(childKind))
				.findFirst()
				.orElse(null);
	}

	/**
	 * Gets the first ancestor {@link SwiftNode} of the given kind(s)
	 * 
	 * @param ancestorKinds The ancestor kinds
	 * @return The first ancestor {@link SwiftNode} of the given kind
	 */
	public SwiftNode getFirstAncestor(SwiftDemangledNodeKind... ancestorKinds) {
		if (ancestorKinds != null && ancestorKinds.length > 0) {
			for (SwiftNode p = parent; p != null; p = p.getParent()) {
				for (SwiftDemangledNodeKind ancestorKind : ancestorKinds) {
					if (p.getKind().equals(ancestorKind)) {
						return p;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Called when this {@link SwiftNode} skipped processing a child during the demangling process.
	 * Used to identify and/or debug missing implementations.
	 * 
	 * @param child The skipped child {@link SwiftNode}
	 */
	public void skip(SwiftNode child) {
		childSkipped = true;
	}
	
	/**
	 * Returns whether or not this {@link SwiftNode} skipped processing any children during the
	 * demangling process
	 * 
	 * @return True if a child {@link SwiftNode} was skipped; otherwise, false
	 */
	public boolean childWasSkipped() {
		return childSkipped;
	}

	/**
	 * Gets a new {@link DemangledUnknown} created from this {@link SwiftNode}
	 * 
	 * @return A new {@link DemangledUnknown} created from this {@link SwiftNode}
	 */
	public DemangledUnknown getUnknown() {
		return new DemangledUnknown(properties.mangled(), properties.originalDemangled(),
			properties.originalDemangled());
	}

	/**
	 * Joins the first {@link Demangled} with the second.  The name of the first will become the 
	 * top-level namespace of the second.
	 * 
	 * @param a The first {@link Demangled} to join
	 * @param b The second {@link Demangled} to join
	 * @return The joined {@link Demangled}s
	 */
	public static Demangled join(Demangled a, Demangled b) {
		if (a == null) {
			return b;
		}
		if (b == null) {
			return a;
		}
		Demangled topNamespace = b;
		while (topNamespace.getNamespace() != null) {
			topNamespace = topNamespace.getNamespace();
		}
		topNamespace.setNamespace(a);
		return b;
	}

	/**
	 * Converts the given {@link SwiftNode} to a string
	 * 
	 * @param node The {@link SwiftNode} to convert to a string
	 * @param recurse True if the {@link SwiftNode} should be recursed; otherwise, false
	 * @return The given {@link SwiftNode} in string form
	 */
	public static String toString(SwiftNode node, boolean recurse) {
		StringBuilder sb = new StringBuilder(node.toString());
		if (recurse) {
			sb.append("\n");
			for (SwiftNode child : node.getChildren()) {
				sb.append(toString(child, true));
			}
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(" ".repeat(properties.depth() * 2));
		sb.append("kind=" + properties.kind());
		if (properties.text() != null) {
			sb.append(", text=\"" + properties.text() + "\"");
		}
		if (properties.index() != null) {
			sb.append(", index=" + properties.index() + "");
		}
		return sb.toString();
	}

	/**
	 * Demangles the first child {@link SwiftNode}, if it exists
	 * 
	 * @param demangler The {@link SwiftDemangler}
	 * @return The demangled first child {@link SwiftNode}
	 * @throws DemangledException if there are no children or another problem occurred
	 */
	protected Demangled demangleFirstChild(SwiftDemangler demangler)
			throws DemangledException {
		Demangled first = null;
		for (int i = 0; i < children.size(); i++) {
			SwiftNode child = children.get(i);
			if (i == 0) {
				first = child.demangle(demangler);
			}
			else {
				child.skip(child);
			}
		}
		if (first == null) {
			throw new DemangledException("No children");
		}
		return first;
	}
}
