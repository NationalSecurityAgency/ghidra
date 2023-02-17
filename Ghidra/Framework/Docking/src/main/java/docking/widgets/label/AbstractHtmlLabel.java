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
package docking.widgets.label;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.StringReader;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.*;
import javax.swing.text.html.*;
import javax.swing.text.html.HTMLDocument.HTMLReader;
import javax.swing.text.html.HTMLEditorKit.ParserCallback;

import docking.widgets.GComponent;
import ghidra.util.Msg;
import ghidra.util.WebColors;
import ghidra.util.exception.AssertException;

/**
 * Base class for labels that render html using a custom rendering kit.
 * <p>
 * This implementation uses custom html rendering.  This custom rendering allows for basic
 * formatting while eliminating potentially unsafe html tags.  If for some reason this custom
 * rendering is deficient, clients can instead use a standard Java {@link JLabel}.
 * <p>
 * Clients do not need to prefix label text with "&lt;html&gt;", as is required for a standard
 * JLabel.
 */
public abstract class AbstractHtmlLabel extends JLabel
		implements GComponent, PropertyChangeListener {

	private static final String HTML_TAG = "<html>";
	private boolean isUpdating;
	private boolean isHtml;

	protected AbstractHtmlLabel() {
		addPropertyChangeListener(this);
	}

	protected AbstractHtmlLabel(String text) {
		super(text);
		addPropertyChangeListener(this);
	}

	@Override
	public void setText(String text) {

		// do not pass <html> up to the parent so that it does not install its own html rendering
		if (text != null && text.toLowerCase().startsWith(HTML_TAG)) {
			text = text.substring(HTML_TAG.length());
			isHtml = true;
		}
		else {
			isHtml = false;
		}

		super.setText(text);

		updateHtmlView();
	}

	@Override
	public void updateUI() {
		super.updateUI();
		updateHtmlView();
	}

	private void updateHtmlView() {

		String text = getText();
		if (text == null || !isHtml || !isHTMLRenderingEnabled()) {
			putClientProperty(BasicHTML.propertyKey, null);
			return;
		}

		// We need to add the html text back for our html editor kit to render html.  Install our
		// own View by the BasicHTML.propertyKey key so that the paint method uses it.
		View customHtmlView = createHTMLView(HTML_TAG + text);
		putClientProperty(BasicHTML.propertyKey, customHtmlView);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {

		if (isUpdating) {
			return;
		}

		String name = evt.getPropertyName();
		if (!BasicHTML.propertyKey.equals(name)) {
			return;
		}
		try {
			isUpdating = true;
			updateHtmlView();
		}
		finally {
			isUpdating = false;
		}
	}

	private View createHTMLView(String html) {
		if (getFont() == null) {
			return null; // initializing
		}

		GHtmlLabelEditorKit editorKit = new GHtmlLabelEditorKit();
		Document document = editorKit.createDefaultDocument(getFont(), getForeground());
		if (document == null) {
			return null;
		}

		StringReader reader = new StringReader(html);
		try {
			editorKit.read(reader, document, 0);
		}
		catch (Throwable e) {
			Msg.debug(this, "Error loading default html styles", e);
			return null;
		}
		ViewFactory factory = editorKit.getViewFactory();
		View view = factory.create(document.getDefaultRootElement());
		return new ViewWrapper(view, factory);
	}

	private class GHtmlLabelEditorKit extends HTMLEditorKit {

		@Override
		public Document createDefaultDocument() {
			StyleSheet baseStyleSheet = getStyleSheet();
			StyleSheet styleSheet = new StyleSheet();

			styleSheet.addStyleSheet(baseStyleSheet);

			HTMLDocument document = new GHtmlLabelDocument(styleSheet, getFont(), getBackground());
			document.setParser(getParser());
			document.setAsynchronousLoadPriority(4);
			document.setTokenThreshold(100);
			return document;
		}

		public Document createDefaultDocument(Font defaultFont, Color foreground) {
			StyleSheet defaultStyleSheet = new StyleSheet();

			String defaultCss = """
					p {
						margin-top: 0;
						margin-bottom: 0;
						margin-left: 0;
						margin-right: 0;
					}
					body {
						margin-top: 0;
						margin-bottom: 0;
						margin-left: 0;
						margin-right: 0;
					}
					""";

			StringReader reader = new StringReader(defaultCss);
			try {
				defaultStyleSheet.loadRules(reader, null);
			}
			catch (Throwable e) {
				Msg.debug(this, "Error loading default html styles", e);
				return null;
			}

			defaultStyleSheet.addStyleSheet(super.getStyleSheet());

			StyleSheet styleSheet = new StyleSheet();
			styleSheet.addStyleSheet(defaultStyleSheet);
			GHtmlLabelDocument document =
				new GHtmlLabelDocument(styleSheet, defaultFont, foreground);
			document.setAsynchronousLoadPriority(Integer.MAX_VALUE);
			return document;
		}
	}

	private class GHtmlLabelDocument extends HTMLDocument {

		public GHtmlLabelDocument(StyleSheet ss, Font font, Color bg) {
			super(ss);
			setPreservesUnknownTags(false);

			// loosely the default values used by HTMLDocument

			String s = """
					body {
						font-family: %s;
						font-size: %spt;
						font-weight: %s;
						font-style: %s;
						color: %s;
					}
					""";

			String family = font.getFamily();
			String size = Integer.toString(font.getSize());
			String weight = font.isBold() ? "700" : "400";
			String style = font.isItalic() ? "italic" : "normal";
			String color = WebColors.toString(bg, false);
			String css = String.format(s, family, size, weight, style, color);
			ss.addRule(css);
		}

		@Override
		public ParserCallback getReader(int pos) {
			return new GHtmlLabelReader(this, pos);
		}
	}

	private class GHtmlLabelReader extends HTMLReader {

		public GHtmlLabelReader(HTMLDocument htmlDocument, int offset) {
			htmlDocument.super(offset);

			//
			// Remove support for any tags we do not need
			// (see HTMLDocument.HTMLReader for default list of tags and actions)
			//
			// Supported Tags:
			// A, B, BLOCKQUOTE, BODY, BR, CENTER, CODE, DIV, FONT, H1, H2, H3, H4, H5, H6, HR,
			// HTML, I, LI, NOBR, OL, P, PRE, SPAN, STRIKE, SUB, SUP, TABLE, TD, TEXTAREA, TH, TR,
			// TT, U, UL
			//
			// (Note: this list was made in a cursory fashion, keeping basic formatting tags while
			// removing any that allow for remote accesses, such as the IMG tag.)
			//

			TagAction stub = new TagAction();
			HTML.Tag[] toRemove = { HTML.Tag.ADDRESS, HTML.Tag.APPLET, HTML.Tag.AREA, HTML.Tag.BASE,
				HTML.Tag.BASEFONT, HTML.Tag.BIG, HTML.Tag.CAPTION, HTML.Tag.CITE, HTML.Tag.DD,
				HTML.Tag.DFN, HTML.Tag.DIR, HTML.Tag.DL, HTML.Tag.DT, HTML.Tag.EM, HTML.Tag.FORM,
				HTML.Tag.FRAME, HTML.Tag.FRAMESET, HTML.Tag.HEAD, HTML.Tag.IMG, HTML.Tag.INPUT,
				HTML.Tag.ISINDEX, HTML.Tag.KBD, HTML.Tag.LINK, HTML.Tag.MAP, HTML.Tag.MENU,
				HTML.Tag.META, HTML.Tag.NOFRAMES, HTML.Tag.OBJECT, HTML.Tag.OPTION, HTML.Tag.PARAM,
				HTML.Tag.SAMP, HTML.Tag.SCRIPT, HTML.Tag.SELECT, HTML.Tag.SMALL, HTML.Tag.S,
				HTML.Tag.STRONG, HTML.Tag.STYLE, HTML.Tag.TITLE, HTML.Tag.VAR };
			replace(toRemove, stub);
		}

		private void replace(HTML.Tag[] tags, TagAction action) {
			for (HTML.Tag tag : tags) {
				registerTag(tag, action);
			}
		}
	}

	private class ViewWrapper extends View {

		private int width;
		private View htmlView;
		private ViewFactory factory;
		private JComponent container;

		ViewWrapper(View view, ViewFactory viewFactory) {
			super(null);
			this.container = AbstractHtmlLabel.this;
			this.htmlView = view;
			this.factory = viewFactory;
			htmlView.setParent(this);

			setSize(htmlView.getPreferredSpan(X_AXIS), htmlView.getPreferredSpan(Y_AXIS));
		}

		@Override
		public float getPreferredSpan(int axis) {
			if (axis == X_AXIS) {
				return width; // have the label use its assigned width
			}
			return htmlView.getPreferredSpan(axis);
		}

		@Override
		public float getMinimumSpan(int axis) {
			return htmlView.getMinimumSpan(axis); // use delegate's minimum
		}

		@Override
		public float getMaximumSpan(int axis) {
			return Integer.MAX_VALUE; // no restrictions
		}

		@Override
		public void preferenceChanged(View child, boolean w, boolean h) {
			container.revalidate();
			container.repaint();
		}

		@Override
		public void paint(Graphics g, Shape allocation) {
			Rectangle alloc = allocation.getBounds();
			htmlView.setSize(alloc.width, alloc.height);
			htmlView.paint(g, allocation);
		}

		@Override
		public void setSize(float w, float h) {
			// have our label always use the available width
			this.width = (int) w;
			htmlView.setSize(w, h);
		}

		@Override
		public void setParent(View parent) {
			throw new AssertException("setParent() unexpectedly called"); // shouldn't happen
		}

		@Override
		public AttributeSet getAttributes() {
			return null; // no special attributes to use outside of the document
		}

		@Override
		public Container getContainer() {
			return container;
		}

		@Override
		public ViewFactory getViewFactory() {
			return factory;
		}

		@Override
		public int getViewCount() {
			return 1;
		}

		@Override
		public View getView(int n) {
			return htmlView;
		}

		@Override
		public Shape modelToView(int pos, Shape a, Position.Bias b) throws BadLocationException {
			return htmlView.modelToView(pos, a, b);
		}

		@Override
		public Shape modelToView(int p0, Position.Bias b0, int p1, Position.Bias b1, Shape a)
				throws BadLocationException {
			return htmlView.modelToView(p0, b0, p1, b1, a);
		}

		@Override
		public int viewToModel(float x, float y, Shape a, Position.Bias[] bias) {
			return htmlView.viewToModel(x, y, a, bias);
		}

		@Override
		public Document getDocument() {
			return htmlView.getDocument();
		}

		@Override
		public int getStartOffset() {
			return htmlView.getStartOffset();
		}

		@Override
		public int getEndOffset() {
			return htmlView.getEndOffset();
		}

		@Override
		public Element getElement() {
			return htmlView.getElement();
		}

		@Override
		public float getAlignment(int axis) {
			return htmlView.getAlignment(axis);
		}
	}
}
