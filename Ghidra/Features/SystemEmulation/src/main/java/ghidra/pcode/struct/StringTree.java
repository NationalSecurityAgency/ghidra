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
package ghidra.pcode.struct;

import java.util.LinkedList;
import java.util.List;

public class StringTree {
	public static StringTree single(CharSequence seq) {
		StringTree st = new StringTree();
		st.append(seq);
		return st;
	}

	interface Node {
		void walk(StringBuffer buf);
	}

	class Branch implements Node {
		List<Node> children = new LinkedList<>();

		void addChild(Node child) {
			children.add(child);
		}

		@Override
		public void walk(StringBuffer buf) {
			for (Node child : children) {
				child.walk(buf);
			}
		}
	}

	class Leaf implements Node {
		final CharSequence seq;

		public Leaf(CharSequence seq) {
			this.seq = seq;
		}

		@Override
		public void walk(StringBuffer buf) {
			buf.append(seq);
		}
	}

	Branch root = new Branch();

	public void append(CharSequence seq) {
		root.addChild(new Leaf(seq));
	}

	public void append(StringTree tree) {
		root.addChild(tree.root);
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		root.walk(buf);
		return buf.toString();
	}
}
