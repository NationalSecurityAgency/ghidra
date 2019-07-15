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
package ghidra.xtext.sleigh.ui;

import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.RGB;
import org.eclipse.xtext.ui.editor.syntaxcoloring.DefaultHighlightingConfiguration;
import org.eclipse.xtext.ui.editor.syntaxcoloring.IHighlightingConfigurationAcceptor;
import org.eclipse.xtext.ui.editor.utils.TextStyle;

public class SleighHighlightingConfiguration extends DefaultHighlightingConfiguration {
	// provide an id string for the highlighting calculator
	public static final String CONTEXTFIELD = "Context Field";
	public static final String TOKENFIELD = "Token Field";
	public static final String SYMBOL = "Symbol";
	public static final String VARIABLE = "Variable";
	public static final String ATTACHEDSYM = "Attached Symbol";
	public static final String PRINTPIECE = "Print Piece";
	public static final String LOCAL = "Local Symbol";
	public static final String SUBTABLE = "SubTable";

	public void configure(IHighlightingConfigurationAcceptor acceptor) {
		super.configure(acceptor);
		addType(acceptor, CONTEXTFIELD, 50, 50, 0, SWT.ITALIC);
		addType(acceptor, TOKENFIELD, 50, 50, 0, SWT.NORMAL);
		addType(acceptor, SYMBOL, 50, 50, 50, TextStyle.DEFAULT_FONT_STYLE);
		addType(acceptor, VARIABLE, 106, 62, 63, SWT.BOLD);
		addType(acceptor, ATTACHEDSYM, 50, 50, 50, SWT.BOLD);
		addType(acceptor, PRINTPIECE, 0,0,255, SWT.BOLD);
		addType(acceptor, LOCAL, 40,40,40, SWT.ITALIC);
		addType(acceptor, SUBTABLE, 192, 82, 5, SWT.NORMAL);
	}

	public void addType(IHighlightingConfigurationAcceptor acceptor, String s,
			int r, int g, int b, int style) {
		addType(acceptor, s, new RGB(r,g,b), style);
	}
	
	public void addType(IHighlightingConfigurationAcceptor acceptor, String s,
			RGB rgb, int style) {
		TextStyle textStyle = new TextStyle();
		textStyle.setBackgroundColor(new RGB(255, 255, 255));
		textStyle.setColor(rgb);
		textStyle.setStyle(style);
		acceptor.acceptDefaultHighlighting(s, s, textStyle);
	}

}
