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

import generic.json.Json;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;

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
	private Function function; // will be null for global highlights
	private Set<ClangDecompilerHighlighter> clones = new HashSet<>();

	ClangDecompilerHighlighter(String id, DecompilerPanel panel, Function function,
			CTokenHighlightMatcher matcher) {
		this.id = id;
		this.decompilerPanel = panel;
		this.function = function;
		this.matcher = matcher;
	}

	private ClangDecompilerHighlighter(DecompilerPanel panel, CTokenHighlightMatcher matcher) {
		UUID uuId = UUID.randomUUID();
		this.id = uuId.toString();
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
		ClangDecompilerHighlighter clone =
			new ClangDecompilerHighlighter(id, panel, function, matcher);
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

		DecompilerController controller = decompilerPanel.getController();
		Function decompiledFunction = controller.getFunction();
		if (function != null && !function.equals(decompiledFunction)) {
			return; // this is a function-specific highlighter and this is not the desired function 
		}

		// This is done by the caller of this method
		// clearHighlights();

		ClangLayoutController layoutModel = decompilerPanel.getLayoutController();
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
		ColorProvider colorProvider = new MappedTokenColorProvider(highlights);
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
		return Json.toString(this, "matcher", "id");
	}

	private class MappedTokenColorProvider implements ColorProvider {

		private Map<ClangToken, Color> highlights;

		MappedTokenColorProvider(Map<ClangToken, Color> highlights) {
			this.highlights = highlights;
		}

		@Override
		public Color getColor(ClangToken token) {
			return highlights.get(token);
		}

		@Override
		public String toString() {
			return "Token Matcher Color " + matcher.toString();
		}
	}
}
