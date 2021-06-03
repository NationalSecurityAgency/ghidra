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
package ghidra.app.plugin.core.printing;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.print.*;
import java.math.BigInteger;
import java.util.Date;

import docking.util.GraphicsUtils;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.internal.EmptyLayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import ghidra.util.DateUtils;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class CodeUnitPrintable implements Printable {

	//private FieldPanel panel;
	private LayoutModel lm;
	private int startIndex;
	private int endIndex;
	private java.util.List<Layout> layouts;
	private double scaleAmount;
	private TaskMonitor monitor;
	private PrintOptionsDialog pod;
	private Book book;
	private PrinterJob job;

	private Date startDate;

	private static final PaintContext PAINT_CONTEXT = new PaintContext();
	static {
		PAINT_CONTEXT.setForegroundColor(Color.BLACK);
		PAINT_CONTEXT.setDefaultBackgroundColor(Color.WHITE);
		PAINT_CONTEXT.setBackgroundColor(Color.white);
		PAINT_CONTEXT.setCursorColor(Color.RED);
		PAINT_CONTEXT.setSelectionColor(new Color(180, 255, 180));
		PAINT_CONTEXT.setHighlightColor(new Color(255, 255, 150));

		PAINT_CONTEXT.setPrinting(true);
	}

	public CodeUnitPrintable(LayoutModel lm, int startIndex, int endIndex, double scaleAmount,
			TaskMonitor monitor, PrintOptionsDialog pod, Book book, PrinterJob job,
			Date startDate) {
		this.lm = lm;
		this.startIndex = startIndex;
		this.endIndex = endIndex;
		this.scaleAmount = scaleAmount;
		this.monitor = monitor;
		this.pod = pod;
		this.book = book;
		this.job = job;
		this.startDate = startDate;

		if (pod.getMonochrome()) {
			PAINT_CONTEXT.setPrintColor(Color.BLACK);
		}
		else {
			PAINT_CONTEXT.setPrintColor(null);
		}
	}

	public CodeUnitPrintable(LayoutModel lm, java.util.List<Layout> layouts, double scaleAmount,
			TaskMonitor monitor, PrintOptionsDialog pod, Book book, PrinterJob job,
			Date startDate) {
		this.lm = lm;
		this.layouts = layouts;
		this.scaleAmount = scaleAmount;
		this.monitor = monitor;
		this.pod = pod;
		this.book = book;
		this.job = job;
		this.startDate = startDate;

		if (pod.getMonochrome()) {
			PAINT_CONTEXT.setPrintColor(Color.BLACK);
		}
		else {
			PAINT_CONTEXT.setPrintColor(null);
		}
	}

	@Override
	public int print(Graphics graphics, PageFormat pageFormat, int pageIndex)
			throws PrinterException {
		Graphics2D g2 = GraphicsUtils.getGraphics2D(graphics);
		g2.setColor(Color.BLACK);

		monitor.setMessage("Printing Page " + (pageIndex + 1));
		monitor.initialize(100);
		if (monitor.isCancelled()) {
			job.cancel();
			return NO_SUCH_PAGE;
		}

		Rectangle rect = new Rectangle((int) pageFormat.getImageableWidth(),
			(int) pageFormat.getImageableHeight());
		if (scaleAmount < 1.0) {
			rect = new Rectangle((int) (pageFormat.getImageableWidth() / scaleAmount),
				(int) (pageFormat.getImageableHeight() / scaleAmount));
		}
		LayoutBackgroundColorManager ls =
			new EmptyLayoutBackgroundColorManager(PAINT_CONTEXT.getBackground());

		g2.translate(pageFormat.getImageableX(), pageFormat.getImageableY());

		//Print header/footer information
		Font originalFont = g2.getFont();
		g2.setFont(pod.getHeaderFont());
		FontMetrics metrics = g2.getFontMetrics(pod.getHeaderFont());
		float bottomPos = (float) pageFormat.getImageableHeight() - metrics.getMaxDescent();
		if (pod.getPrintTitle()) {
			GraphicsUtils.drawString(null, g2, job.getJobName(), 0, metrics.getMaxAscent());
		}
		if (pod.getPrintDate()) {
			String dateTime = DateUtils.formatDateTimestamp(startDate);
			GraphicsUtils.drawString(null, g2, dateTime, 0, (int) bottomPos);
		}
		if (pod.getPrintPageNum()) {
			String pageString = "Page " + (pageIndex + 1) + " of " + book.getNumberOfPages();
			GraphicsUtils.drawString(null, g2, pageString,
				(int) (pageFormat.getImageableWidth() - metrics.stringWidth(pageString)),
				(int) bottomPos);
		}
		g2.setFont(originalFont);
		if (pod.showHeader()) {
			g2.translate(0, pod.getHeaderHeight());
		}

		if (scaleAmount < 1.0) {
			g2.transform(AffineTransform.getScaleInstance(scaleAmount, scaleAmount));
		}

		if (layouts != null) {
			//If no layouts, ignore blank page
			if (layouts.size() == 0) {
				return NO_SUCH_PAGE;
			}
			for (int i = 0; i < layouts.size(); i++) {
				Layout layout = layouts.get(i);
				try {
					if (layout != null) {
						layout.paint(null, g2, PAINT_CONTEXT, rect, ls, null);
						g2.translate(0, layout.getHeight());
					}
				}
				catch (Exception e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					i = endIndex + 1;
				}
				monitor.setProgress((i + 1) * 100 / layouts.size());
			}
		}
		else {
			for (int i = startIndex; i <= endIndex; i++) {
				Layout layout = lm.getLayout(BigInteger.valueOf(i));
				try {
					if (layout != null) {
						layout.paint(null, g2, PAINT_CONTEXT, rect, ls, null);
						g2.translate(0, layout.getHeight());
					}
				}
				catch (Exception e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					i = endIndex + 1;
				}
				monitor.setProgress((i - startIndex + 1) * 100 / (endIndex - startIndex + 1));
			}
		}

		return PAGE_EXISTS;
	}

}
