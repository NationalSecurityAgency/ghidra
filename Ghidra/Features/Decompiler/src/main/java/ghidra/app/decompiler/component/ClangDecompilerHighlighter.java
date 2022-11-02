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
package ghidra.app.decompiler.component;

import java.awt.Color;
import java.util.*;
import java.util.function.Supplier;

import ghidra.app.decompiler.*;

/**
 * The implementation of {@link DecompilerHighlighter}.  This will get created by the
 * Decompiler and then handed to clients that use the {@link DecompilerHighlightService}.  This
 * is also used internally for 'secondary highlights'.
 * 
 * <p>This class may be {@link #clone() cloned} or {@link #copy(DecompilerPanel) copied} as
 * needed when the user creates a snapshot.  Highlight service highlighters will be cloned;
 * secondary highlighters will be copied.  Cloning allows this class to delegate highlighting
 * and cleanup for clones.  Contrastingly, copying allows the secondary highlights to operate
 * independently.
 */
class ClangDecompilerHighlighter implements DecompilerHighlighter {

	protected String id;
	private DecompilerPanel decompilerPanel;
	private CTokenHighlightMatcher matcher;
	private Set<ClangDecompilerHighlighter> clones = new HashSet<>();

	ClangDecompilerHighlighter(DecompilerPanel panel, CTokenHighlightMatcher matcher) {
		UUID uuId = UUID.randomUUID();
		this.id = uuId.toString();
		this.decompilerPanel = panel;
		this.matcher = matcher;
	}

	ClangDecompilerHighlighter(String id, DecompilerPanel panel, CTokenHighlightMatcher matcher) {
		this.id = id;
		this.decompilerPanel = panel;
		this.matcher = matcher;
	}

	/**
	 * Create a clone of this highlighter and tracks the clone
	 * @param panel the panel
	 * @return the highlighter
	 */
	ClangDecompilerHighlighter clone(DecompilerPanel panel) {
		// note: we re-use the ID to make tracking easier
		ClangDecompilerHighlighter clone = new ClangDecompilerHighlighter(id, panel, matcher);
		clones.add(clone);
		return clone;
	}

	/**
	 * Creates a copy of this highlighter that is not tracked by this highlighter
	 * @param panel the panel
	 * @return the highlighter
	 */
	ClangDecompilerHighlighter copy(DecompilerPanel panel) {
		return new ClangDecompilerHighlighter(panel, matcher);
	}

	@Override
	public void applyHighlights() {

		if (decompilerPanel == null) {
			return; // disposed
		}

		clearHighlights();

		ClangLayoutController layoutModel =
			(ClangLayoutController) decompilerPanel.getLayoutModel();
		ClangTokenGroup root = layoutModel.getRoot();

		Map<ClangToken, Color> highlights = new HashMap<>();
		try {
			matcher.start(root);
			gatherHighlights(root, highlights);
		}
		finally {
			matcher.end();
		}

		Supplier<? extends Collection<ClangToken>> tokens = () -> highlights.keySet();
		ColorProvider colorProvider = t -> highlights.get(t);
		decompilerPanel.addHighlighterHighlights(this, tokens, colorProvider);

		clones.forEach(c -> c.applyHighlights());
	}

	private void gatherHighlights(ClangTokenGroup root, Map<ClangToken, Color> results) {

		int n = root.numChildren();
		for (int i = 0; i < n; ++i) {
			ClangNode child = root.Child(i);
			getHighlight(child, results);

			if (child instanceof ClangTokenGroup) {
				gatherHighlights(((ClangTokenGroup) child), results);
			}
		}
	}

	private void getHighlight(ClangNode node, Map<ClangToken, Color> results) {
		if (node instanceof ClangTokenGroup) {
			return;
		}

		ClangToken token = (ClangToken) node;
		Color color = matcher.getTokenHighlight(token);
		if (color != null) {
			results.put(token, color);
		}
	}

	@Override
	public void clearHighlights() {
		if (decompilerPanel == null) {
			return; // disposed
		}

		decompilerPanel.removeHighlighterHighlights(this);
		clones.forEach(c -> c.clearHighlights());
	}

	@Override
	public void dispose() {
		if (decompilerPanel == null) {
			return; // disposed
		}

		clearHighlights();
		decompilerPanel.removeHighlighter(id);
		decompilerPanel = null;
		clones.forEach(c -> c.dispose());
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public String toString() {
		return super.toString() + ' ' + id;
	}
}
