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
package ghidra.app.util.demangler.swift;

import java.io.IOException;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.swift.SwiftNativeDemangler.SwiftNativeDemangledOutput;
import ghidra.app.util.demangler.swift.nodes.SwiftNode;
import ghidra.app.util.demangler.swift.nodes.SwiftNode.NodeProperties;
import ghidra.app.util.demangler.swift.nodes.SwiftUnsupportedNode;

/**
 * A Swift demangled symbol, structured as a tree of {@link SwiftNode nodes}
 * <p>
 * For example, the <code>Swift.print</code> function's mangled form is 
 * <code>_$ss5print_9separator10terminatoryypd_S2StF</code>, and its demangled tree is:
 * <pre>
 * kind=Global
 * kind=Function
 *   kind=Module, text="Swift"
 *   kind=Identifier, text="print"
 *   kind=LabelList
 *     kind=FirstElementMarker
 *     kind=Identifier, text="separator"
 *     kind=Identifier, text="terminator"
 *   kind=Type
 *     kind=FunctionType
 *       kind=ArgumentTuple
 *         kind=Type
 *           kind=Tuple
 *             kind=TupleElement
 *               kind=VariadicMarker
 *               kind=Type
 *                 kind=ProtocolList
 *                   kind=TypeList
 *             kind=TupleElement
 *               kind=Type
 *                 kind=Structure
 *                   kind=Module, text="Swift"
 *                   kind=Identifier, text="String"
 *             kind=TupleElement
 *               kind=Type
 *                 kind=Structure
 *                   kind=Module, text="Swift"
 *                   kind=Identifier, text="String"
 *       kind=ReturnType
 *         kind=Type
 *           kind=Tuple
 * </pre>
 */
public class SwiftDemangledTree {

	private static final Pattern KIND_PATTERN = Pattern.compile("kind=([^,]+)");
	private static final Pattern TEXT_PATTERN = Pattern.compile("text=\"(.+)\"");
	private static final Pattern INDEX_PATTERN = Pattern.compile("index=(.+)");

	private SwiftNode root;
	private String demangledString;

	/**
	 * Creates a new {@link SwiftDemangledTree}
	 * 
	 * @param nativeDemangler The Swift native demangler
	 * @param mangled The mangled string
	 * @throws DemangledException If there was an issue demangling
	 */
	public SwiftDemangledTree(SwiftNativeDemangler nativeDemangler, String mangled)
			throws DemangledException {
		SwiftNativeDemangledOutput demangledOutput;
		try {
			demangledOutput = nativeDemangler.demangle(mangled);
		}
		catch (IOException e) {
			throw new DemangledException(e);
		}
		demangledString = demangledOutput.demangled();
		Stack<SwiftNode> stack = new Stack<>();
		for (String line : demangledOutput.tree()) {
			int depth = depth(line);
			String kind = match(line, KIND_PATTERN);
			String text = match(line, TEXT_PATTERN);
			String index = match(line, INDEX_PATTERN);
			SwiftNode node;
			try {
				NodeProperties properties = new NodeProperties(SwiftDemangledNodeKind.valueOf(kind),
					text, index, depth, mangled, demangledString);
				node = SwiftNode.get(properties);
			}
			catch (IllegalArgumentException e) {
				NodeProperties properties = new NodeProperties(SwiftDemangledNodeKind.Unsupported,
					text, index, depth, mangled, demangledString);
				node = new SwiftUnsupportedNode(kind, properties);
			}
			if (node.getDepth() == 0) {
				root = node;
			}
			else {
				if (node.getDepth() <= stack.peek().getDepth()) {
					while (stack.peek().getDepth() > node.getDepth() - 1) {
						stack.pop();
					}
				}
				node.setParent(stack.peek());
				stack.peek().getChildren().add(node);
			}
			stack.push(node);
		}
	}

	/**
	 * Gets the root {@link SwiftNode} of the tree
	 * 
	 * @return The root {@link SwiftNode} of the tree.  Could be null if demangling finished 
	 *   gracefully but did not return a result.
	 */
	public SwiftNode getRoot() {
		return root;
	}

	/**
	 * Gets the demangled string
	 * 
	 * @return The demangled string.  Could be null if demangling finished gracefully
	 *   but did not return a result.
	 */
	public String getDemangledString() {
		return demangledString;
	}

	@Override
	public String toString() {
		return SwiftNode.toString(root, true);
	}

	/**
	 * Gets the tree-depth of this {@link SwiftNode}
	 * 
	 * @param line A line of output from <code>swift demangle --tree-only</code>
	 * @return The tree-depth of this {@link SwiftNode}
	 */
	private int depth(String line) {
		int i = 0;
		while (i < line.length() && line.charAt(i) == ' ') {
			i++;
		}
		return i / 2;
	}

	/**
	 * Gets a matched pattern on the given line
	 * 
	 * @param line The line to match against
	 * @param pattern The {@link Pattern} to match
	 * @return The matched string, or null if there was no match
	 */
	private String match(String line, Pattern pattern) {
		Matcher matcher = pattern.matcher(line);
		return matcher.find() ? matcher.group(1) : null;
	}
}
