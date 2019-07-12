package ghidra.app.decompiler.component;

import java.awt.Color;

import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.program.model.listing.Function;

public class HighlightToken {
	private ClangToken token;
	private Color color;
	private DecompilerPanel panel;

	public HighlightToken(ClangToken token, Color color, Function func) {
		this.token = token;
		this.color = color;
	}

	/**
	 * Compares two HighlightTokens.
	 *
	 * Two HighlightTokens are equal if their text is equal
	 * and if they reside in the same function.
	 */
	@Override
	public boolean equals(Object obj) {
		ClangToken otherToken = null;

		if (obj.getClass() == HighlightToken.class) {
			HighlightToken hltoken = (HighlightToken)obj;
			otherToken = hltoken.token;
		}
		
		if (obj.getClass() == ClangToken.class) {
			otherToken = ((ClangToken) obj);
		}
		
		if (obj.getClass() == ClangVariableToken.class) {
			otherToken = ((ClangToken) obj);
		}
		
		if (otherToken == null) {
			return false;
		}
		Function func1 = otherToken.getClangFunction().getHighFunction().getFunction();
		Function func2 = this.token.getClangFunction().getHighFunction().getFunction();
		return otherToken.getText().equals(this.token.getText()) &&
				(func1.equals(func2));
	}

	public ClangToken getToken() {
		return token;
	}

	public void setToken(ClangToken token) {
		this.token = token;
	}

	public Color getColor() {
		return color;
	}

	public void setColor(Color color) {
		this.color = color;
	}

	public DecompilerPanel getPanel() {
		return panel;
	}

	public void setPanel(DecompilerPanel panel) {
		this.panel = panel;
	}

	public Function getFunction() {
		if (token == null) {
			return null;
		}
		ClangFunction clangFunc = token.getClangFunction();
		if (clangFunc == null) {
			return null;
		}
		return clangFunc.getHighFunction().getFunction();
	}
}
