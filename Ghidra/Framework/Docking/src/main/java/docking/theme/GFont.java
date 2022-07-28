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
package docking.theme;

import java.awt.Font;
import java.awt.font.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.text.AttributedCharacterIterator.Attribute;
import java.text.CharacterIterator;
import java.util.*;

public class GFont extends Font implements Refreshable {

	private String id;
	private Font delegate;

	public GFont(String id) {
		super("Courier", Font.PLAIN, 12);
		this.id = id;
		delegate = Gui.getRawFont(id);
		if (delegate == null) {
			delegate = new Font("Courier", Font.PLAIN, 12);
		}
	}

	public boolean isEquivalent(Font font) {
		return delegate.equals(font);
	}

	public String getId() {
		return id;
	}

	@Override
	public AffineTransform getTransform() {
		return delegate.getTransform();
	}

	@Override
	public void refresh() {
		Font font = Gui.getRawFont(id);
		if (font != null) {
			delegate = font;
		}
	}

	@Override
	public String getFamily() {
		return delegate.getFamily();
	}

	@Override
	public String getFamily(Locale l) {
		return delegate.getFamily(l);
	}

	@Override
	public String getPSName() {
		return delegate.getPSName();
	}

	@Override
	public String getName() {
		return delegate.getName();
	}

	@Override
	public String getFontName() {
		return delegate.getFontName();
	}

	@Override
	public String getFontName(Locale l) {
		return delegate.getFontName(l);
	}

	@Override
	public int getStyle() {

		return delegate.getStyle();
	}

	@Override
	public int getSize() {
		return delegate.getSize();
	}

	@Override
	public float getSize2D() {
		return delegate.getSize2D();
	}

	@Override
	public boolean isPlain() {
		return delegate.isPlain();
	}

	@Override
	public boolean isBold() {
		return delegate.isBold();
	}

	@Override
	public boolean isItalic() {
		return delegate.isItalic();
	}

	@Override
	public boolean isTransformed() {
		return delegate.isTransformed();
	}

	@Override
	public boolean hasLayoutAttributes() {
		return delegate.hasLayoutAttributes();
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GFont other = (GFont) obj;
		return Objects.equals(id, other.id);
	}

	@Override
	public String toString() {
		return delegate.toString();
	}

	@Override
	public int getNumGlyphs() {
		return delegate.getNumGlyphs();
	}

	@Override
	public int getMissingGlyphCode() {
		return delegate.getMissingGlyphCode();
	}

	@Override
	public byte getBaselineFor(char c) {
		return delegate.getBaselineFor(c);
	}

	@Override
	public Map<TextAttribute, ?> getAttributes() {
		return delegate.getAttributes();
	}

	@Override
	public Attribute[] getAvailableAttributes() {
		return delegate.getAvailableAttributes();
	}

	@Override
	public Font deriveFont(int newStyle, float newSize) {
		return delegate.deriveFont(newStyle, newSize);
	}

	@Override
	public Font deriveFont(int newStyle, AffineTransform trans) {
		return delegate.deriveFont(newStyle, trans);
	}

	@Override
	public Font deriveFont(float newSize) {
		return delegate.deriveFont(newSize);
	}

	@Override
	public Font deriveFont(AffineTransform trans) {
		return delegate.deriveFont(trans);
	}

	@Override
	public Font deriveFont(int newStyle) {
		return delegate.deriveFont(newStyle);
	}

	@Override
	public Font deriveFont(Map<? extends Attribute, ?> attributes) {
		return delegate.deriveFont(attributes);
	}

	@Override
	public boolean canDisplay(char c) {
		return delegate.canDisplay(c);
	}

	@Override
	public boolean canDisplay(int codePoint) {
		return delegate.canDisplay(codePoint);
	}

	@Override
	public int canDisplayUpTo(String str) {
		return delegate.canDisplayUpTo(str);
	}

	@Override
	public int canDisplayUpTo(char[] text, int start, int limit) {
		return delegate.canDisplayUpTo(text, start, limit);
	}

	@Override
	public int canDisplayUpTo(CharacterIterator iter, int start, int limit) {
		return delegate.canDisplayUpTo(iter, start, limit);
	}

	@Override
	public float getItalicAngle() {
		return delegate.getItalicAngle();
	}

	@Override
	public boolean hasUniformLineMetrics() {
		return delegate.hasUniformLineMetrics();
	}

	@Override
	public LineMetrics getLineMetrics(String str, FontRenderContext frc) {
		return delegate.getLineMetrics(str, frc);
	}

	@Override
	public LineMetrics getLineMetrics(String str, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getLineMetrics(str, beginIndex, limit, frc);
	}

	@Override
	public LineMetrics getLineMetrics(char[] chars, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getLineMetrics(chars, beginIndex, limit, frc);
	}

	@Override
	public LineMetrics getLineMetrics(CharacterIterator ci, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getLineMetrics(ci, beginIndex, limit, frc);
	}

	@Override
	public Rectangle2D getStringBounds(String str, FontRenderContext frc) {
		return delegate.getStringBounds(str, frc);
	}

	@Override
	public Rectangle2D getStringBounds(String str, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getStringBounds(str, beginIndex, limit, frc);
	}

	@Override
	public Rectangle2D getStringBounds(char[] chars, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getStringBounds(chars, beginIndex, limit, frc);
	}

	@Override
	public Rectangle2D getStringBounds(CharacterIterator ci, int beginIndex, int limit,
			FontRenderContext frc) {
		return delegate.getStringBounds(ci, beginIndex, limit, frc);
	}

	@Override
	public Rectangle2D getMaxCharBounds(FontRenderContext frc) {
		return delegate.getMaxCharBounds(frc);
	}

	@Override
	public GlyphVector createGlyphVector(FontRenderContext frc, String str) {
		return delegate.createGlyphVector(frc, str);
	}

	@Override
	public GlyphVector createGlyphVector(FontRenderContext frc, char[] chars) {
		return delegate.createGlyphVector(frc, chars);
	}

	@Override
	public GlyphVector createGlyphVector(FontRenderContext frc, CharacterIterator ci) {
		return delegate.createGlyphVector(frc, ci);
	}

	@Override
	public GlyphVector createGlyphVector(FontRenderContext frc, int[] glyphCodes) {
		return delegate.createGlyphVector(frc, glyphCodes);
	}

	@Override
	public GlyphVector layoutGlyphVector(FontRenderContext frc, char[] text, int start, int limit,
			int flags) {
		return delegate.layoutGlyphVector(frc, text, start, limit, flags);
	}
}
