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
package ghidra.bsfv;

import java.awt.Color;
import java.util.*;

import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.Gui;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.*;

/**
 * This class is used to highlight tokens in the decompiler corresponding to BSim features
 */
class BsfvTokenHighlightMatcher implements CTokenHighlightMatcher {

	private static final Color DEFAULT_HIGHLIGHT = Palette.ORANGE;
	private static final Color LINE_HIGHLIGHT_COLOR = Palette.getColor("lightskyblue");
	private static final Color SECONDARY_LINE_HIGHLIGHT_COLOR = Palette.getColor("steelblue");

	private PcodeOpAST pcodeOp;
	private PcodeOpAST previousPcodeOp;
	private PcodeBlockBasic block;
	private Set<Integer> lineHighlights;
	private Set<Integer> secondaryLineHighlights;
	private Set<Integer> blockHighlights;
	private Options graphOptions;

	public BsfvTokenHighlightMatcher(BsfvRowObject row, HighFunction highFunction,
			BSimFeatureVisualizerPlugin plugin) {
		graphOptions =
			plugin.getTool().getOptions("Graph").getOptions(BSimFeatureGraphType.OPTIONS_NAME);
		switch (row.getBSimFeatureType()) {
			case DATA_FLOW:
				this.pcodeOp = row.getPcodeOpAST();
				break;
			case COPY_SIG:
				//just highlight block
				//could improve by finding the standalone copies and only highlighting them
			case CONTROL_FLOW:
				this.block = highFunction.getBasicBlocks().get(row.getBlockIndex());
				break;
			case COMBINED:
				this.block = highFunction.getBasicBlocks().get(row.getBlockIndex());
				this.pcodeOp = row.getPcodeOpAST();
				break;
			case DUAL_FLOW:
				this.block = highFunction.getBasicBlocks().get(row.getBlockIndex());
				this.pcodeOp = row.getPcodeOpAST();
				this.previousPcodeOp = row.getPreviousPcodeOpAST();
				break;
			default:
				throw new IllegalArgumentException(
					"Unsupported feature type: " + row.getBSimFeatureType().toString());
		}
	}

	/**
	 * Creates a highlighter for DATA_FLOW features
	 * @param pcodeOp defining pcode op
	 */
	public BsfvTokenHighlightMatcher(PcodeOpAST pcodeOp) {
		this.pcodeOp = pcodeOp;
	}

	/**
	 * Creates a highlighter for CONTROL_FLOW features
	 * @param block base block
	 */
	public BsfvTokenHighlightMatcher(PcodeBlockBasic block) {
		this.block = block;
	}

	/**
	 * Creates a highlighter for COMBINED features
	 * @param pcodeOp root op
	 * @param block root block
	 */
	public BsfvTokenHighlightMatcher(PcodeOpAST pcodeOp, PcodeBlockBasic block) {
		this.pcodeOp = pcodeOp;
		this.block = block;
	}

	/**
	 * Creates a highlighter for DUAL_FLOW features
	 * @param pcodeOp pcode op
	 * @param previousPcodeOp previous pcode op
	 */
	public BsfvTokenHighlightMatcher(PcodeOpAST pcodeOp, PcodeOpAST previousPcodeOp) {
		this.pcodeOp = pcodeOp;
		this.previousPcodeOp = previousPcodeOp;
	}

	@Override
	public void start(ClangNode root) {
		lineHighlights = new HashSet<>();
		secondaryLineHighlights = new HashSet<>();
		blockHighlights = new HashSet<>();

		if (pcodeOp != null) {
			List<ClangToken> opTokens =
				DecompilerUtils.getTokens(root, pcodeOp.getSeqnum().getTarget());
			for (ClangToken token : opTokens) {
				lineHighlights.add(token.getLineParent().getLineNumber());
			}
		}

		if (previousPcodeOp != null) {
			List<ClangToken> secondaryOpTokens =
				DecompilerUtils.getTokens(root, previousPcodeOp.getSeqnum().getTarget());
			for (ClangToken token : secondaryOpTokens) {
				secondaryLineHighlights.add(token.getLineParent().getLineNumber());
			}
		}

		if (block != null) {
			AddressSet blockRange = new AddressSet(block.getStart(), block.getStop());
			List<ClangToken> tokensInBlock = DecompilerUtils.getTokens(root, blockRange);
			for (ClangToken token : tokensInBlock) {
				ClangLine line = token.getLineParent();
				if (line != null) {
					blockHighlights.add(line.getLineNumber());
				}
			}
		}
	}

	@Override
	public Color getTokenHighlight(ClangToken token) {
		Options options = graphOptions.getOptions("Vertex Colors");
		String opKey = BSimFeatureGraphType.PCODE_OP_VERTEX;
		Color color = options.getColor(opKey, DEFAULT_HIGHLIGHT);
		if (token instanceof ClangFuncNameToken) {
			PcodeOp op = token.getPcodeOp();
			if (op == null) {
				return null;
			}
			if (pcodeOp != null && op.getSeqnum().equals(pcodeOp.getSeqnum())) {
				return color;
			}
			if (previousPcodeOp != null && op.getSeqnum().equals(previousPcodeOp.getSeqnum())) {
				return Gui.darker(color);
			}
		}
		if (token instanceof ClangOpToken) {
			PcodeOp op = token.getPcodeOp();
			if (op == null) {
				return null;
			}
			if (pcodeOp != null && op.getSeqnum().equals(pcodeOp.getSeqnum())) {
				return color;
			}
			if (previousPcodeOp != null && op.getSeqnum().equals(previousPcodeOp.getSeqnum())) {
				return Gui.darker(color);
			}
		}
		if (token instanceof ClangVariableToken) {
			ClangVariableToken varToken = (ClangVariableToken) token;
			PcodeOp op = varToken.getPcodeOp();
			Varnode vnode = varToken.getVarnode();
			if (op == null) {
				return null;
			}
			if (pcodeOp != null && op.getSeqnum().equals(pcodeOp.getSeqnum())) {
				if (vnode != null && vnode.equals(op.getOutput())) {
					return options.getColor(BSimFeatureGraphType.BASE_VARNODE_VERTEX,
						DEFAULT_HIGHLIGHT);
				}
			}
			if (previousPcodeOp != null && op.getSeqnum().equals(previousPcodeOp.getSeqnum())) {
				if (vnode != null && vnode.equals(op.getOutput())) {
					return options.getColor(BSimFeatureGraphType.SECONDARY_BASE_VARNODE_VERTEX,
						DEFAULT_HIGHLIGHT);
				}
			}
		}
		if (token.getLineParent() != null) {
			if (lineHighlights.contains(token.getLineParent().getLineNumber())) {
				return LINE_HIGHLIGHT_COLOR;
			}
			if (secondaryLineHighlights.contains(token.getLineParent().getLineNumber())) {
				return SECONDARY_LINE_HIGHLIGHT_COLOR;
			}
			if (blockHighlights.contains(token.getLineParent().getLineNumber())) {
				return options.getColor(BSimFeatureGraphType.BASE_BLOCK_VERTEX, DEFAULT_HIGHLIGHT);
			}
		}
		return null;
	}

}
