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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.*;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.Icon;
import javax.swing.JPanel;

import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import generic.theme.GIcon;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.component.margin.DecompilerMarginProvider;
import ghidra.app.decompiler.component.margin.LayoutPixelIndexMap;
import ghidra.program.model.listing.Program;

@SuppressWarnings("serial")
public class TaintDecompilerMarginProvider extends JPanel
		implements DecompilerMarginProvider, LayoutModelListener {

	// TODO: Extend the ClangLine class and include an equals and hashCode method so it 
	//       works properly with sets.  This will be better than strings because it could
	//       include line number and deconflict when there are two IDENTICAL lines in the source
	//       code.

	private LayoutModel model;
	private LayoutPixelIndexMap pixmap;

	private final TaintPlugin plugin;

	// NOTE: ClangLine doesn't have an equals or hashCode method, so we use strings.
	private Set<String> sourceAddresses = new HashSet<>();
	private Set<String> sinkAddresses = new HashSet<>();
	private Set<String> gateAddresses = new HashSet<>();

	// These icon property names go in your Theme properties files in the <home>/.ghidra directory tree
	// The format: icon.decompiler.taint.source = /path/to/the/icon.png

	private Icon sourceIcon = new GIcon("icon.plugin.scriptmanager.run");
	private Icon sinkIcon = new GIcon("icon.stop");
	private Icon gateIcon = new GIcon("icon.debugger.breakpoint.set");

	public TaintDecompilerMarginProvider(TaintPlugin plugin) {
		this.plugin = plugin;
		setPreferredSize(new Dimension(16, 0));
	}

	@Override
	public void setProgram(Program program, LayoutModel model, LayoutPixelIndexMap pixmap) {
		setLayoutManager(model);
		this.pixmap = pixmap;
		repaint();
	}

	public void functionChanged() {
		repaint();
	}

	private void setLayoutManager(LayoutModel model) {
		if (this.model == model) {
			return;
		}
		if (this.model != null) {
			this.model.removeLayoutModelListener(this);
		}
		this.model = model;
		if (this.model != null) {
			this.model.addLayoutModelListener(this);
		}
	}

	@Override
	public Component getComponent() {
		return this;
	}

	@Override
	public void modelSizeChanged(IndexMapper indexMapper) {
		repaint();
	}

	@Override
	public void dataChanged(BigInteger start, BigInteger end) {
		repaint();
	}

	@Override
	public void paint(Graphics g) {
		super.paint(g);
		if (plugin.getDecompilerProvider() == null) {
			return;
		}
		Rectangle visible = getVisibleRect();
		BigInteger startIdx = pixmap.getIndex(visible.y);
		BigInteger endIdx = pixmap.getIndex(visible.y + visible.height);

		List<ClangLine> lines = plugin.getDecompilerProvider().getDecompilerPanel().getLines();
		for (BigInteger index = startIdx; index.compareTo(endIdx) <= 0; index =
			index.add(BigInteger.ONE)) {

			int i = index.intValue();
			if (i >= lines.size()) {
				continue;
			}

			ClangLine line = lines.get(i);
			if (sourceAddresses.contains(line.toString())) {
				sourceIcon.paintIcon(this, g, 0, pixmap.getPixel(index));
			}

			if (sinkAddresses.contains(line.toString())) {
				sinkIcon.paintIcon(this, g, 0, pixmap.getPixel(index));
			}

			if (gateAddresses.contains(line.toString())) {
				gateIcon.paintIcon(this, g, 0, pixmap.getPixel(index));
			}
		}
	}

	/**
	 * @param label - SOURCE, SINK, etc.
	 */
	public void toggleIcon(TaintLabel label) {
		Set<String> addresses = switch (label.getType()) {
			case SOURCE -> sourceAddresses;
			case SINK -> sinkAddresses;
			case GATE -> gateAddresses;
			default -> null;
		};
		if (addresses != null) {
			String cline = label.getClangLine().toString();
			if (label.isActive()) {
				addresses.add(cline);
			}
			else {
				addresses.remove(cline);
			}
			repaint();
		}
	}

	public void clearIcons() {
		sourceAddresses.clear();
		sinkAddresses.clear();
		gateAddresses.clear();
	}

}
