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
package docking.widgets.search;

import java.awt.*;

import javax.swing.*;
import javax.swing.text.View;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GThemeDefaults.Colors;
import ghidra.docking.settings.Settings;
import ghidra.util.layout.AbstractLayoutManager;
import ghidra.util.table.column.AbstractGColumnRenderer;

/**
 * A renderer for {@link SearchLocationContext}.  This renderer handles the complexity of rendering
 * html text with clipping.
 */
public abstract class SearchLocationContextRenderer
		extends AbstractGColumnRenderer<SearchLocationContext> {

	private JPanel htmlContainer = new JPanel(new HtmlTruncatingLayout());
	private JLabel ellipsisLabel = new JLabel("...");

	public SearchLocationContextRenderer() {
		setHTMLRenderingEnabled(true);
	}

	protected abstract SearchLocationContext getContext(GTableCellRenderingData data);

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		SearchLocationContext context = getContext(data);
		return renderHtmlContext(data, context);
	}

	public Component renderPlainContext(GTableCellRenderingData data,
			SearchLocationContext context) {

		super.getTableCellRendererComponent(data);

		// Note: we do not include the line number prefix on the text, based on the assumption that
		// clients of this renderer will have a separate line number column.
		String text = context.getPlainText(false);
		setText(text);
		return this;
	}

	public Component renderHtmlContext(GTableCellRenderingData data,
			SearchLocationContext context) {

		// initialize
		super.getTableCellRendererComponent(data);

		/*
		 	We have html context.  Build a renderer that is a panel with 2 children: the html label
		 	(this renderer object) and an ellipsis label that will be visible as needed. 
		 */

		// Note: we do not include the line number prefix on the text, based on the assumption that
		// clients of this renderer will have a separate line number column.
		String html = context.getBoldMatchingText(false);
		setText(html);

		ellipsisLabel.setOpaque(true);
		ellipsisLabel.setForeground(Colors.FOREGROUND);
		ellipsisLabel.setBackground(getBackground());

		htmlContainer.setBackground(getBackground());
		htmlContainer.removeAll();
		htmlContainer.add(this);
		htmlContainer.add(ellipsisLabel);

		return htmlContainer;
	}

	@Override
	public String getFilterString(SearchLocationContext rowObject, Settings settings) {
		return rowObject.getPlainText();
	}

	/**
	 * A layout manager that positions 2 labels: a leading label with html and a trailing label
	 * with an ellipsis, which may not be visible.  JLabels rendering html will not show an
	 * ellipsis when clipped.   We use these 2 labels here to show when the leading html label's
	 * text is clipped.
	 */
	private class HtmlTruncatingLayout extends AbstractLayoutManager {

		@Override
		public Dimension preferredLayoutSize(Container parent) {

			Dimension d = new Dimension();
			int n = parent.getComponentCount();
			for (int i = 0; i < n; i++) {
				Component c = parent.getComponent(i);
				Dimension cd = c.getPreferredSize();
				d.width += cd.width;
				d.height = Math.max(d.height, cd.height);
			}

			Insets insets = parent.getInsets();
			d.width += insets.left + insets.right;
			d.height += insets.top + insets.bottom;
			return d;
		}

		@Override
		public void layoutContainer(Container parent) {
			// Assumption: the leading component is an html view; the trailing component is a
			// label with an ellipsis

			JComponent c1 = (JComponent) parent.getComponent(0);
			Dimension d = parent.getSize();
			Insets insets = parent.getInsets();
			int width = d.width - insets.left - insets.right;

			View v = (View) c1.getClientProperty("html");
			Insets i = c1.getInsets();
			int availableWidth = width - (i.left + i.right);
			int htmlw = (int) v.getPreferredSpan(View.X_AXIS);

			JLabel c2 = (JLabel) parent.getComponent(1);
			Dimension c2d = c2.getPreferredSize();
			boolean isClipped = htmlw > availableWidth && width != 0;
			if (isClipped) {
				availableWidth -= c2d.width; // save room for ellipsis
				int c2x = availableWidth;
				int c2y = insets.top;
				c2.setBounds(c2x, c2y, c2d.width, c2d.height);
			}

			c2.setVisible(isClipped);

			int c1x = insets.left;
			int c1y = insets.top;
			int cyh = d.height - (i.top + i.bottom);
			c1.setBounds(c1x, c1y, availableWidth, cyh);
		}
	}
}
