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
package help.screenshot;

import java.awt.*;
import java.awt.image.BufferedImage;

import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.ComponentProvider;
import docking.DockableComponent;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;

public class DecompilePluginScreenShots extends GhidraScreenShotGenerator {
	private static final Color DARK_BLUE = new Color(0, 0, 128);
	private static final Color DARK_GREEN = new Color(0, 128, 0);
	private static final Color YELLOW_ORANGE = new Color(155, 150, 50);
	private static final Color PURPLE = new Color(155, 50, 155);

	public DecompilePluginScreenShots() {
		super();
	}

	@Test
	public void testDecompWindow() {
		removeFlowArrows();
		goToListing(0x401055);
		closeProvider(ViewManagerComponentProvider.class);
		closeProvider(DataTypesProvider.class);
		ComponentProvider provider = getProvider("Decompiler");
		showProvider(provider.getClass());
		setDividerPercentage(CodeViewerProvider.class, provider.getClass(), .50f);
		captureWindow(tool.getToolFrame(), 1000, 500);
		DockableComponent comp = getDockableComponent(provider.getClass());
		Rectangle bounds = comp.getBounds();
		bounds = SwingUtilities.convertRectangle(comp.getParent(), bounds, null);
		crop(new Rectangle(0, bounds.y, 1000, bounds.height));
	}

	@Test
	public void testDefuse() {
		TextFormatter tf = new TextFormatter(17, 400, 4, 5, 0);
		TextFormatterContext hl = new TextFormatterContext(Color.BLACK, Color.YELLOW);
		TextFormatterContext red = new TextFormatterContext(Color.RED, Color.WHITE);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE, Color.WHITE);
		TextFormatterContext green = new TextFormatterContext(Color.GREEN, Color.WHITE);
		TextFormatterContext cursorhl =
			new TextFormatterContext(Color.BLACK, Color.YELLOW, Color.RED);

		tf.writeln("|void| |max_retry|(node *ptr)", blue, red);
		tf.writeln("");
		tf.writeln("{");
		tf.writeln("    dword a;");
		tf.writeln("    sdword b;");
		tf.writeln("    ");
		tf.writeln("    |a| = ptr->max + |7|", cursorhl, green);
		tf.writeln("    b = ptr->prev->max + |a|;", hl);
		tf.writeln("    |if| ((sdword)(ptr->next->max + |a|) < |7|) {", blue, hl, green);
		tf.writeln("        ptr->max = |a|;", hl);
		tf.writeln("    }");
		tf.writeln("    |else| {", blue);
		tf.writeln("        a = ptr->max + |6|", green);
		tf.writeln("    }");
		tf.writeln("    ptr->next->max = a + b");
		tf.writeln("    |return|;", blue);
		tf.writeln("}");
		image = tf.getImage();
	}

	@Test
	public void testForwardSlice() {
		TextFormatter tf = new TextFormatter(16, 500, 4, 5, 0);
		TextFormatterContext hl = new TextFormatterContext(Color.BLACK, Color.YELLOW);
		TextFormatterContext red = new TextFormatterContext(Color.RED);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext green = new TextFormatterContext(Color.GREEN);
		TextFormatterContext cursorhl =
			new TextFormatterContext(Color.BLACK, Color.YELLOW, Color.RED);

		tf.writeln("    a = psParm2->id;");
		tf.writeln("    |b| = |max_alpha|(psParm1->next,psParm1->id);", cursorhl, red);
		tf.writeln("    c = |max_beta|(psParm1->prev, a);", red);
		tf.writeln("    |c| = c + |b|;", hl, hl);
		tf.writeln("    dStack8 = |0|;", green);
		tf.writeln("    |while| (psParm1->count != dStack8 && (sdword)dStack8) {", blue);
		tf.writeln("        |if| (|c| < (sdword)(dStack8 + |b|)) {", blue, hl, hl);
		tf.writeln("            |c| = |c| + a;", hl, hl);
		tf.writeln("        }");
		tf.writeln("        |else| {", blue);
		tf.writeln("            a = a + |10|;", green);
		tf.writeln("        }");
		tf.writeln("        dStack8 = dStack8 + |1|;", green);
		tf.writeln("    }");
		tf.writeln("    psParm1->count = a + |c|;", hl);
		tf.writeln("    |return|;", blue);

		image = tf.getImage();
	}

	@Test
	public void testBackwardSlice() {
		TextFormatter tf = new TextFormatter(16, 500, 4, 5, 0);
		TextFormatterContext hl = new TextFormatterContext(Color.BLACK, Color.YELLOW);
		TextFormatterContext red = new TextFormatterContext(Color.RED, Color.WHITE);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE, Color.WHITE);
		TextFormatterContext green = new TextFormatterContext(Color.GREEN, Color.WHITE);
		TextFormatterContext greenhl = new TextFormatterContext(Color.GREEN, Color.YELLOW);
		TextFormatterContext cursorhl =
			new TextFormatterContext(Color.BLACK, Color.YELLOW, Color.RED);

		tf.writeln("    |a| = |psParm2|->id;", hl, hl);
		tf.writeln("    b = |max_alpha|(|psParm1|->next,|psParm1|->id);", red, hl, hl);
		tf.writeln("    c = |max_beta|(psParm1->prev, |a|);", red, hl);
		tf.writeln("    c = c + b;");
		tf.writeln("    dStack8 = |0|;", green);
		tf.writeln("    |while| (psParm1->count != dStack8 && (sdword)dStack8) {", blue);
		tf.writeln("        |if| (c < (sdword)(dStack8 + b)) {", blue);
		tf.writeln("            c = c + |a|;", hl);
		tf.writeln("        }");
		tf.writeln("        |else| {", blue);
		tf.writeln("            |a| = |a| + |10|;", hl, hl, greenhl);
		tf.writeln("        }");
		tf.writeln("        dStack8 = dStack8 + |1|;", green);
		tf.writeln("    }");
		tf.writeln("    psParm1->count = |a| + c;", cursorhl);
		tf.writeln("    |return|;", blue);

		image = tf.getImage();
	}

	@Test
	public void testStructnotapplied() {
		Image listingImage = getListingImage();
		Image decompImage = getDecompilerNoStructImage();
		int listingWidth = listingImage.getWidth(null);
		int decompWidth = decompImage.getWidth(null);
		int height = Math.max(listingImage.getHeight(null), decompImage.getHeight(null));
		BufferedImage combined = createEmptyImage(listingWidth + decompWidth, height);
		Graphics2D g = combined.createGraphics();
		g.drawImage(listingImage, 0, 0, null);
		g.drawImage(decompImage, listingWidth, 0, null);
		g.dispose();
		image = combined;
	}

	public void testStructApplied() {
		Image listingImage = getListingImage();
		Image decompImage = getDecompilerStructAppliedImage();
		int listingWidth = listingImage.getWidth(null);
		int decompWidth = decompImage.getWidth(null);
		int height = Math.max(listingImage.getHeight(null), decompImage.getHeight(null));
		BufferedImage combined = createEmptyImage(listingWidth + decompWidth, height);
		Graphics2D g = combined.createGraphics();
		g.drawImage(listingImage, 0, 0, null);
		g.drawImage(decompImage, listingWidth, 0, null);
		g.dispose();
		image = combined;
	}

	@Test
	public void testEditFunctionSignature() {
		goToListing(0x401040);
		ComponentProvider provider = getProvider("Decompiler");
		showProvider(provider.getClass());
		waitForSwing();
		performAction("Edit Function Signature", "DecompilePlugin", provider, false);
		captureDialog();
	}

	private Image getListingImage() {
		Font font = new Font("Monospaced", Font.PLAIN, 12);

		TextFormatter tf = new TextFormatter(font, 15, 400, 4, 14, 1);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext darkBlue = new TextFormatterContext(DARK_BLUE);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);
		TextFormatterContext purple = new TextFormatterContext(PURPLE);
		tf.colorLines(new Color(180, 255, 180), 9, 1);

		// @formatter:off
		tf.writeln("|8b 40 0c|     |MOV|    |EAX|,|Oxc|[|EAX|]", blue, darkBlue, orange, darkGreen, orange );
		tf.writeln("|3b 45 fc|     |CMP|    |EAX|,|local_8|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|79 29|        |JLE|    |LAB_080483c6|", blue, darkBlue, darkBlue );
		tf.writeln("|8b 55 08|     |MOV|    |EDX|,|psParm1|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 45 fc|     |MOV|    |EAX|,|local_8|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|89 42 0c|     |MOV|    |0xC|,|[EDX]||EAX|", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 45 08|     |MOV|    |EAX|,|psParm1|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 50 08|     |MOV|    |EAX|,|0x4|[|EAX|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 45 08|     |MOV|    |EAX|,|psParm1|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 40 04|     |MOV|    |EAX|,|0x4|[|EAX|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|89 42 04|     |MOV|    |0x4|,|[EDX]||EAX|", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 45 08|     |MOV|    |EAX|,|psParm1|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 50 04|     |MOV|    |EDX|,|0x4|[|EAX|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 45 08|     |MOV|    |EAX|,|psParm1|[|EBP|]", blue, darkBlue, orange, purple, orange );
		tf.writeln("|8b 40 08|     |MOV|    |EAX|,|0x8|[|EAX|]", blue, darkBlue, orange, purple, orange );
		// @formatter:on

		return tf.getImage();
	}

	private Image getDecompilerNoStructImage() {
		Font font = new Font("Monospaced", Font.PLAIN, 13);

		TextFormatter tf = new TextFormatter(font, 15, 400, 4, 2, 0);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext green = new TextFormatterContext(Color.GREEN);
		TextFormatterContext hl = new TextFormatterContext(Color.BLACK, Color.YELLOW);
		TextFormatterContext greenhl = new TextFormatterContext(Color.GREEN, Color.YELLOW);
		TextFormatterContext cursor = new TextFormatterContext(Color.WHITE, Color.WHITE, Color.RED);

		// @formatter:off
		tf.writeln("  dword dVar1:");
		tf.writeln("              ");
		tf.writeln("  dVar1 = sParm2[*psParm1];");
		tf.writeln("  |if| ((sdword)dVar1 < psParm1[|3|]) {", blue, green);
		tf.writeln("    psParm1[|3|] = dVar1;", green);
		tf.writeln("| |   |*(sdword *)psParm1[2] + ||4||) == psParm1[||1||];|",cursor, hl, greenhl, hl, greenhl, hl);
		tf.writeln("    *(sdword *)psParm1[1] + |8|) == psParm1[|2|];", green, green);
		tf.writeln("  }");
		tf.writeln("  |else| {", blue);
		tf.writeln("    |if| (dVar1 - psParm1[|3|] == |0|) {", blue, green, green);
		tf.writeln("      psParm1[|4|] = |100|;", green, green);
		tf.writeln("    }");
		tf.writeln("  	|else| {", blue);
		tf.writeln("      psParm1[|4|] = dVar1 - psParm1[|3|];", green, green);
		tf.writeln("  }");

		// @formatter:on

		return tf.getImage();
	}

	private Image getDecompilerStructAppliedImage() {
		Font font = new Font("Monospaced", Font.PLAIN, 13);

		TextFormatter tf = new TextFormatter(font, 15, 400, 4, 2, 0);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext green = new TextFormatterContext(Color.GREEN);
		TextFormatterContext hl = new TextFormatterContext(Color.BLACK, Color.YELLOW);
		TextFormatterContext cursor = new TextFormatterContext(Color.WHITE, Color.WHITE, Color.RED);

		// @formatter:off
		tf.writeln("  dword dVar1:");
		tf.writeln("              ");
		tf.writeln("  dVar1 = sParm2[psParm1->id];");
		tf.writeln("  |if| ((sdword)dVar1 < (sdword)psParm1->max) {", blue);
		tf.writeln("    psParm1->max = dVar1;");
		tf.writeln("| |   |psParm1->prev->next == psParm1->next;|",cursor,hl);
		tf.writeln("    psParm1->next->prev == psParm1->prev;");
		tf.writeln("  }");
		tf.writeln("  |else| {", blue);
		tf.writeln("    |if| (dVar1 - psParm1->max == |0|) {", blue, green);
		tf.writeln("      psParm1->count = |100|;", green);
		tf.writeln("    }");
		tf.writeln("  	|else| {", blue);
		tf.writeln("      psParm1->count = dVar1 - psParm1->max;");
		tf.writeln("  }");

		// @formatter:on

		return tf.getImage();
	}
}
