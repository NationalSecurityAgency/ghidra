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
package ghidra.app.decompiler;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * An iterator over ClangToken objects.  The iterator walks a tree of ClangNode objects based on
 * the Parent() and Child() methods, returning successive ClangNode leaf objects that are also
 * ClangToken objects.  The iterator can run either forward or backward over the tokens.
 * 
 * The constructor TokenIterator(ClangToken,int) initializes the iterator to start at the given
 * token, which can be in the middle of the sequence.
 */
public class TokenIterator implements Iterator<ClangToken> {

	private ClangTokenGroup[] nodeStack;	// Ancestry of current ClangToken
	private ClangToken currentToken;				// Current ClangToken
	private int[] indexStack;		// Indices into ClangTokenGroup
	private int depth;				// Depth of current token
	private int direction;		// -1 = iterating backward 1 = iterating forward

	/**
	 * Expand the arrays holding the node stack so that at least one more ClangNode can be added
	 */
	private void expand() {
		int size = (nodeStack.length < 256) ? nodeStack.length * 2 : nodeStack.length + 512;
		ClangTokenGroup[] newNodeStack = new ClangTokenGroup[size];
		int[] newIndexStack = new int[size];
		System.arraycopy(nodeStack, 0, newNodeStack, 0, nodeStack.length);
		System.arraycopy(indexStack, 0, newIndexStack, 0, indexStack.length);
		nodeStack = newNodeStack;
		indexStack = newIndexStack;
	}

	/**
	 * Add a new ClangTokenGroup to the node stack
	 * @param group is the new group being pushed
	 */
	private void pushGroup(ClangTokenGroup group) {
		depth += 1;
		if (depth >= nodeStack.length) {
			expand();
		}
		nodeStack[depth] = group;
		indexStack[depth] = (direction < 0) ? group.numChildren() - 1 : 0;
	}

	/**
	 * Backtrack until:
	 *   - all indices indicate a proper child for their respective token group
	 * Then push forward until:
	 *   - the active node at the current depth is a ClangToken
	 */
	private void normalize() {
		int index = indexStack[depth];
		if (index < 0) {
			depth -= 1;
			if (depth < 0) {
				currentToken = null;
				return;
			}
			indexStack[depth] -= 1;
			normalize();
			return;
		}
		ClangTokenGroup group = nodeStack[depth];
		if (index >= group.numChildren()) {
			depth -= 1;
			if (depth < 0) {
				currentToken = null;
				return;
			}
			indexStack[depth] += 1;
			normalize();
			return;
		}
		ClangNode node = group.Child(index);
		if (node instanceof ClangToken) {
			currentToken = (ClangToken) node;
			return;
		}
		pushGroup((ClangTokenGroup) node);
		normalize();
	}

	/**
	 * Update the node stack so that it points to the next ClangToken.  The next token is either
	 * the predecessor or the successor depending on the direction setting (-1 or 1) respectively.
	 * currentToken is set to the next token.  If there is no next token, currentToken is set to null.
	 */
	private void advanceToken() {
		if (currentToken == null) {
			return;
		}
		indexStack[depth] += direction;
		normalize();
	}

	private static int findIndex(ClangNode group, ClangNode node) {
		for (int i = 0; i < group.numChildren(); ++i) {
			if (group.Child(i) == node) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Initialize an iterator to a point to a specific ClangToken, which may be anywhere in the sequence.
	 * @param token is the specific ClangToken
	 * @param forward is true for a forward iterator, false for a backward iterator
	 */
	public TokenIterator(ClangToken token, boolean forward) {
		ArrayList<ClangTokenGroup> groupList = new ArrayList<>();
		ClangNode node = token.Parent();
		while (node != null) {
			groupList.add((ClangTokenGroup) node);
			node = node.Parent();
		}
		nodeStack = new ClangTokenGroup[groupList.size()];
		indexStack = new int[groupList.size()];
		node = token;
		for (int i = 0; i < nodeStack.length; ++i) {
			ClangTokenGroup group = groupList.get(i);
			nodeStack[nodeStack.length - 1 - i] = group;
			indexStack[nodeStack.length - 1 - i] = findIndex(group, node);
			node = group;
		}
		currentToken = token;
		direction = forward ? 1 : -1;
		depth = nodeStack.length - 1;
	}

	/**
	 * Create iterator across all tokens under the given ClangTokenGroup.  The iterator will walk the
	 * entire tree of token groups under the given group.  The iterator will run over tokens in display
	 * order (forward=true) or in reverse of display order (forward=false)
	 * @param group is the given ClangTokenGroup
	 * @param forward is true for a forward iterator, false for a backward iterator
	 */
	public TokenIterator(ClangTokenGroup group, boolean forward) {
		ArrayList<ClangTokenGroup> groupList = new ArrayList<>();
		ClangNode node = group;
		while (node instanceof ClangTokenGroup) {
			ClangTokenGroup curGroup = (ClangTokenGroup) node;
			groupList.add(curGroup);
			if (forward) {
				node = curGroup.Child(0);
			}
			else {
				node = curGroup.Child(curGroup.numChildren() - 1);
			}
		}
		nodeStack = new ClangTokenGroup[groupList.size()];
		indexStack = new int[groupList.size()];
		groupList.toArray(nodeStack);
		for (int i = 0; i < indexStack.length; ++i) {
			indexStack[i] = forward ? 0 : nodeStack[i].numChildren() - 1;
		}
		currentToken = (ClangToken) node;
		direction = forward ? 1 : -1;
		depth = nodeStack.length - 1;
	}

	@Override
	public boolean hasNext() {
		return (currentToken != null);
	}

	@Override
	public ClangToken next() {
		ClangToken res = currentToken;
		advanceToken();
		return res;
	}

}
