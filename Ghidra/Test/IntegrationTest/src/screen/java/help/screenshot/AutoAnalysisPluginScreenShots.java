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
import java.util.concurrent.CountDownLatch;

import org.junit.Test;

import docking.DialogComponentProvider;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;

public class AutoAnalysisPluginScreenShots extends GhidraScreenShotGenerator {

	public AutoAnalysisPluginScreenShots() {
		super();
	}

	@Override
	public void loadDefaultTool() {
		// not tool for this test
	}

	@Test
	public void testAutoAnalysis() {
		Color darkGreen = Palette.GREEN;
		Color navy = Palette.getColor("navy");
		image = new BufferedImage(700, 400, BufferedImage.TYPE_INT_ARGB);
		Graphics g = image.getGraphics();
		g.setColor(Colors.BACKGROUND);
		g.fillRect(0, 0, 700, 400);

		drawText("(1) User Disassembles Code", Colors.FOREGROUND, new Point(160, 30), 24);
		drawArrow(navy, new Point(325, 35), new Point(325, 70));
		drawText("(new code)", darkGreen, new Point(270, 90), 24);

		drawText("(2) Function Analyzer", Colors.FOREGROUND, new Point(0, 150), 24);
		drawArrow(navy, new Point(265, 82), new Point(180, 120));
		drawText("(new function)", darkGreen, new Point(100, 190), 24);

		drawText("(3) Stack Analyzer", Colors.FOREGROUND, new Point(10, 230), 24);
		drawArrow(navy, new Point(50, 155), new Point(50, 205));

		drawText("(4) Operand Analyzer", Colors.FOREGROUND, new Point(180, 290), 24);
		drawArrow(navy, new Point(300, 94), new Point(300, 260));
		drawText("(5) Data Reference Analyzer", Colors.FOREGROUND, new Point(280, 350), 24);
		drawArrow(navy, new Point(350, 94), new Point(490, 325));

		Point p1 = new Point(447, 355);
		Point p2 = new Point(447, 395);
		Point p3 = new Point(690, 395);

		drawLine(navy, 3, p1, p2);
		drawLine(navy, 3, p2, p3);
		drawArrow(navy, p3, new Point(404, 88));
	}

	@Test
	public void testCaptureAutoAnalysisOptions() {
		showAnalysisOptions("Data Reference");
		captureDialog(800, 400);
	}

	@Test
	public void testCaptureBackgroundAnalysisTasks() throws InterruptedException {
		CountDownLatch start = new CountDownLatch(1);
		CountDownLatch end = new CountDownLatch(1);
		TestBackgroundCommand cmd = new TestBackgroundCommand(start, end);
		tool.executeBackgroundCommand(cmd, program);
		start.await();
		waitForSwing();
		captureWindow();
		end.countDown();
		int width = image.getWidth(null);
		int height = image.getHeight(null);
		crop(new Rectangle(width - 400, height - 120, 400, 120));
	}

	@Test
	public void testCaptureProgramOptions() {
		showProgramOptions("Analyzers");
		DialogComponentProvider dialog = getDialog();
		Component comp = findComponentByName(dialog.getComponent(), "Analysis Panel");
		setSelectedAnayzer(comp, "Reference");
		captureDialog(1000, 600);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	class TestBackgroundCommand extends BackgroundCommand {

		private CountDownLatch start;
		private CountDownLatch end;

		TestBackgroundCommand(CountDownLatch start, CountDownLatch end) {
			super("Test", true, true, false);
			this.start = start;
			this.end = end;
			setStatusMsg("Applying Function Signatures");
		}

		@Override
		public boolean applyTo(DomainObject obj, final TaskMonitor monitor) {
			monitor.initialize(100);
			monitor.setProgress(65);
			monitor.setMessage("Applying Function Signatures");
			runSwing(() -> invokeInstanceMethod("update", monitor));

			start.countDown();
			try {
				end.await();
			}
			catch (InterruptedException e) {
				// so what?
			}
			return true;
		}
	}

}
