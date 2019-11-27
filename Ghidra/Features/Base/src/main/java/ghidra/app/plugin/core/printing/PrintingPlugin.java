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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.print.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.*;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.support.AnchoredLayout;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Print Selections of code",
	description = "Allows user to select areas of code in the listing window andsend that to a printer in a similar format as the screen is showing.",
	servicesRequired = { CodeViewerService.class }
)
//@formatter:on
public class PrintingPlugin extends ProgramPlugin {
	private static final String NAME = "PrintingPlugin";

	private DockingAction printAction;
	private DockingAction pageSetupAction;
	private CodeViewerService cvService;

	PrintOptionsDialog pod;

	//private PrinterJob job = PrinterJob.getPrinterJob();
	private PageFormat format;

	public PrintingPlugin(PluginTool tool) {
		super(tool, true, true);
		setupActions();
	}

	@Override
	public void init() {
		super.init();
		cvService = tool.getService(CodeViewerService.class);
	}

	@Override
	protected void programActivated(Program program) {
		printAction.setEnabled(true);
		pageSetupAction.setEnabled(true);
	}

	@Override
	protected void programDeactivated(Program program) {
		printAction.setEnabled(false);
		pageSetupAction.setEnabled(false);
	}

	private void setupActions() {
		printAction = new PrintAction();
		tool.addAction(printAction);

		pageSetupAction = new PageSetupAction();
		tool.addAction(pageSetupAction);
	}

	class PrintAction extends DockingAction {
		public PrintAction() {
			super("Print", PrintingPlugin.NAME);
			// ACTIONS - auto generated
			MenuData menuData =
				new MenuData(new String[] { ToolConstants.MENU_FILE, "&Print..." }, null, "Print");
			menuData.setMenuSubGroup("a");
			setMenuBarData(menuData);
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, InputEvent.CTRL_DOWN_MASK));

			setEnabled(false);
			setHelpLocation(new HelpLocation("PrintingPlugin", "Print"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (pod == null) {
				pod = new PrintOptionsDialog(currentSelection != null);
			}
			else {
				pod.setSelectionEnabled(currentSelection != null);
			}
			tool.showDialog(pod);

			if (pod.isCancelled()) {
				return;
			}

			Task printTask = new Task("Printing", true, true, true) {
				@Override
				public void run(TaskMonitor monitor) {

					monitor.setMessage("Constructing Print Job");
					Date startDate = new Date();
					final PrinterJob job = PrinterJob.getPrinterJob();
					job.setJobName("Ghidra - " + currentProgram.getName());
					final Book book = new Book();

					if (format == null) {
						format = job.defaultPage();
					}

					LayoutModel lm = cvService.getFieldPanel().getLayoutModel();
					//Scale everything down if appropriate to fit on the page
					double scaleAmount =
						format.getImageableWidth() / lm.getPreferredViewSize().width;
					int scaledHeight = (int) format.getImageableHeight();
					int headerHeight = (pod.showHeader() ? pod.getHeaderHeight() : 0) +
						(pod.showFooter() ? pod.getHeaderHeight() : 0);
					scaledHeight -= headerHeight;
					if (scaleAmount < 1.0) {
						scaledHeight = (int) (scaledHeight / scaleAmount);
					}

					//If the user only wants to print the selection, print only the selection
					if (pod.getSelection()) {
						printSelection(monitor, startDate, job, book, lm, scaleAmount,
							scaledHeight);
						if (monitor.isCancelled()) {
							return;
						}
					}

					//If the user only wants to print what's on the screen
					else if (pod.getVisible()) {
						printVisibleContent(monitor, startDate, job, book, lm, scaleAmount,
							scaledHeight);
						if (monitor.isCancelled()) {
							return;
						}
					}

					//Otherwise, print the entire document
					else {
						int pageCount =
							getPrintablePageCount(monitor, lm, scaledHeight, BigInteger.ZERO, null);
						printView(monitor, startDate, job, book, lm, scaleAmount, scaledHeight,
							pageCount, BigInteger.ZERO, null);
						if (monitor.isCancelled()) {
							return;
						}
					}

					job.setPageable(book);
					monitor.setMessage("Displaying Print Dialog");
					showPrinterDialogOnSwingThread(job);
				}

				private int getPrintablePageCount(TaskMonitor monitor, LayoutModel lm,
						int pageHeight, BigInteger startIndex, BigInteger termIndex) {
					int currentPageHt = 0;
					int pageCount = 0;
					monitor.initialize(lm.getNumIndexes().longValue());
					for (LayoutModelIterator it = lm.iterator(startIndex); it.hasNext() &&
						!monitor.isCancelled();) {
						Layout layout = it.next();

						// if a terminating index was specified (ie. we are printing a subset
						// of the view), and we've reached it, end the loop.
						// The termIndex is inclusive, ie. the contents of the item pointed 
						// to by the termIndex are used.
						if (termIndex != null && termIndex.compareTo(it.getIndex()) < 0) {
							break;
						}

						if (layout != null) {
							int layoutHt = layout.getHeight();
							if (currentPageHt + layoutHt > pageHeight) {
								// Start a new page.
								// Either kick the offending element's height to the next page, 
								// or if this element is the first item on the page and its
								// bigger than the entire page, just start a fresh page 
								currentPageHt = (currentPageHt == 0) ? 0 : layoutHt;
								pageCount++;
								monitor.setMessage("Counting pages: " + pageCount);
							}
							else {
								currentPageHt += layoutHt;
							}
							monitor.incrementProgress(1);
						}
					}
					return pageCount + (currentPageHt > 0 ? 1 : 0);
				}

				private void printView(TaskMonitor monitor, Date startDate, PrinterJob job,
						Book book, LayoutModel lm, double scaleAmount, int maxPageHeight,
						int pageCount, BigInteger startIndex, BigInteger termIndex) {

					int pageNum = 0;
					BigInteger pageStartIndex = null;
					BigInteger lastIndex = null;
					int currentPageHt = 0;
					long indexCount = (termIndex == null) ? lm.getNumIndexes().longValue()
							: termIndex.subtract(startIndex).longValue();

					monitor.initialize(indexCount);
					monitor.setMessage("Printing...");

					// loop over Layout elements, measuring their height until we get enough
					// for each page.
					// Create a printable page using the pageStartIndex of the element at the top of 
					// the page.
					for (LayoutModelIterator it = lm.iterator(startIndex); it.hasNext() &&
						!monitor.isCancelled(); /* blank */) {
						Layout layout = it.next();

						// if a terminating index was specified (ie. we are printing a subset
						// of the view), and we've reached it, end the loop.
						// The termIndex is inclusive, ie. the contents of the item pointed 
						// to by the termIndex are used.
						if (termIndex != null && termIndex.compareTo(it.getIndex()) < 0) {
							break;
						}

						lastIndex = it.getIndex();
						if (pageStartIndex == null) {
							pageStartIndex = it.getIndex();
						}

						if (layout != null) {
							// I'm not sure you can get a layout == null using the iterator, but cya
							int layoutHt = layout.getHeight();

							if (currentPageHt + layoutHt > maxPageHeight) {
								int psi = pageStartIndex.intValue();

								boolean atBeginningOfNewPageAndElementIsBiggerThanEntirePage =
									psi == it.getIndex().intValue(); // or currentPageHt == 0 would do same thing

								if (atBeginningOfNewPageAndElementIsBiggerThanEntirePage) {
									book.append(new CodeUnitPrintable(lm, psi, psi, scaleAmount,
										monitor, pod, book, job, startDate), format);
									currentPageHt = 0;
									pageStartIndex = null;
								}
								else {
									book.append(new CodeUnitPrintable(lm, psi,
										it.getPreviousIndex().intValue(), scaleAmount, monitor, pod,
										book, job, startDate), format);

									// kick the offending element to new page
									currentPageHt = layoutHt;
									pageStartIndex = it.getIndex();
								}

								pageNum++;
								monitor.setMessage(
									"Constructing Print Job, page " + pageNum + " of " + pageCount);
							}
							else {
								currentPageHt += layoutHt;
							}
							monitor.incrementProgress(1);
						}
					}

					if (!monitor.isCancelled() && lastIndex != null && pageStartIndex != null &&
						lastIndex.compareTo(pageStartIndex) >= 0) {
						monitor.setProgress(indexCount);

						//Put whatever remains on the last page						
						book.append(new CodeUnitPrintable(lm, pageStartIndex.intValue(),
							lastIndex.intValue(), scaleAmount, monitor, pod, book, job, startDate),
							format);
					}
				}

				private void printVisibleContent(TaskMonitor monitor, Date startDate,
						PrinterJob job, Book book, LayoutModel lm, double scaleAmount,
						int maxPageHeight) {
					FieldPanel fp = cvService.getFieldPanel();
					List<AnchoredLayout> visibleLayouts = fp.getVisibleLayouts();
					BigInteger startIndex = visibleLayouts.get(0).getIndex();
					BigInteger endIndex = visibleLayouts.get(visibleLayouts.size() - 1).getIndex();
					int pageCount =
						getPrintablePageCount(monitor, lm, maxPageHeight, startIndex, endIndex);
					printView(monitor, startDate, job, book, lm, scaleAmount, maxPageHeight,
						pageCount, startIndex, endIndex);
				}

				private void printSelection(TaskMonitor monitor, Date startDate, PrinterJob job,
						Book book, LayoutModel lm, double scaleAmount, int scaledHeight) {

					List<Layout> layouts = new ArrayList<>();
					BigInteger lastIndex = null;
					int pageHeight = 0;
					AddressIndexMap indexMap = cvService.getAddressIndexMap();
					AddressRangeIterator rangeItr = currentSelection.getAddressRanges();

					monitor.initialize(currentSelection.getNumAddresses());

					int rangeProgress = 0;

					while (rangeItr.hasNext()) {
						AddressRange curRange = rangeItr.next();
						Address curAddress = curRange.getMinAddress();
						while (curAddress.compareTo(curRange.getMaxAddress()) <= 0) {
							//Add the layout for the present address
							BigInteger curIndex = indexMap.getIndex(curAddress);
							
							// curIndex may be null when processing resource images; just 
							// move to the next address and try again.
							if (curIndex == null) {
								curAddress = curAddress.next();
								
								if (curAddress == null) {
									break;
								}
								
								continue;
							}
							
							if (!curIndex.equals(lastIndex)) {
								Layout layout = lm.getLayout(curIndex);
								if (layout != null) {
									pageHeight += layout.getHeight();
									if (pageHeight > scaledHeight) {
										book.append(new CodeUnitPrintable(lm, layouts, scaleAmount,
											monitor, pod, book, job, startDate), format);
										pageHeight = layout.getHeight();
										layouts = new ArrayList<>();
									}

									layouts.add(layout);
								}

								//Get the next Address and update the page index
								curAddress = curAddress.next();
								monitor.incrementProgress(1);
								if (curAddress == null) {
									break;
								}
								lastIndex = curIndex;
							}
						}

						if (monitor.isCancelled()) {
							return;
						}

						rangeProgress += curRange.getLength();
						monitor.setProgress(rangeProgress);
					}

					monitor.setProgress(currentSelection.getNumAddresses());
					book.append(new CodeUnitPrintable(lm, layouts, scaleAmount, monitor, pod, book,
						job, startDate), format);
				}

			};

			TaskLauncher.launch(printTask);

		}
	}

	private void showPrinterDialogOnSwingThread(final PrinterJob job) {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (job.printDialog()) {
						try {
							job.print();
						}
						catch (Exception e) {
							// let the user see the issue
							Msg.showError(this, null, "Print Failed",
								"Unexpected Exception: " + e.getMessage(), e);
						}
					}
				}
			});
		}
		catch (InterruptedException e) {
			Msg.showError(null, null, "Printing Error", "Printing task interrupted");
		}
		catch (InvocationTargetException e) {
			// shouldn't happen
			Msg.showError(null, null, "Printing Error", "Unexpected error printing: ", e);
		}
	}

	class PageSetupAction extends DockingAction {
		public PageSetupAction() {
			super("Page Setup", PrintingPlugin.NAME);
			// ACTIONS - auto generated
			MenuData menuData = new MenuData(
				new String[] { ToolConstants.MENU_FILE, "Page Setup..." }, null, "Print");
			menuData.setMenuSubGroup("b");
			setMenuBarData(menuData);

			setEnabled(false);
			setHelpLocation(new HelpLocation("PrintingPlugin", "Page_Setup"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			new Thread() {
				@Override
				public void run() {
					PrinterJob job = PrinterJob.getPrinterJob();

					if (format == null) {
						format = job.defaultPage();
					}

					//Delay to avoid silly focus problems
					//try { Thread.sleep(500); } catch (InterruptedException ie) {}
					format = job.pageDialog(format);
				}
			}.start();
		}
	}

	public static String getDescriptiveName() {
		return "Print CodeBrowser Text";
	}

	public static String getDescription() {
		return "Prints text from the CodeBrowser to a printer.";
	}

	public static String getCategory() {
		return "Printing";
	}
}
