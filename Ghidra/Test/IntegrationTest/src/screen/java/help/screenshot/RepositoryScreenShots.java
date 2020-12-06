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

import static org.junit.Assert.*;

import java.awt.*;
import java.math.BigInteger;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import org.junit.*;

import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.test.TestUtils;
import ghidra.app.cmd.function.AddRegisterParameterCommand;
import ghidra.app.merge.*;
import ghidra.app.merge.listing.*;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.TitledPanel;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.*;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class RepositoryScreenShots extends AbstractListingMergeManagerTest {

	protected TestEnv env;
	protected MergeScreenShotGenerator mtfGenerator;
	static protected float DESCRIPTION_FONT_SIZE = (float) 14.0;

	public RepositoryScreenShots() {
		super();
	}

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();
		String testFilename = getClass().getSimpleName().replace(".class", "");
		mtfGenerator = new MergeScreenShotGenerator(testFilename, testName.getMethodName(), mtf, testName);
		env = mtf.getTestEnvironment();
	}

	@After
	@Override
	public void tearDown() throws Exception {
		mtfGenerator.showResults();
		mtf.dispose();
	}

	@Override
	protected void executeMerge(int decision) throws Exception {
		super.executeMerge(decision);
		mtfGenerator.setTool(mergeTool);
	}

	@Override
	protected void executeMerge(int decision, boolean waitForVisibleWindow) throws Exception {
		super.executeMerge(decision, waitForVisibleWindow);
		mtfGenerator.setTool(mergeTool);
	}

//	public void testMultiUser() throws Exception {
//		GhidraScreenShotGenerator gssg = new GhidraScreenShotGenerator(getName());
//		gssg.setUp();
//		gssg.captureWindow();
//
//	}

	@Test
	public void testMemoryConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("Modify Latest Program");
				try {
					blocks[1].setName("LatestText");
					commit = true;
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				int transactionID = program.startTransaction("Modify My Program");
				try {
					blocks[1].setName("MY_Text");
				}
				catch (LockException e) {
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		MergeResolver[] mergeResolvers =
			(MergeResolver[]) TestUtils.getInstanceField("mergeResolvers", mergeMgr);
		Object memoryMergeManager = mergeResolvers[0];
		Container memoryMergePanel =
			(Container) TestUtils.getInstanceField("mergePanel", memoryMergeManager);
		Container namePanel = (Container) TestUtils.getInstanceField("namePanel", memoryMergePanel);
		setToolSize(600, 450);
		Window window = mergeTool.getActiveWindow();
		
		mtfGenerator.captureComponent(window);

//		chooseRadioButton(MergeConstants.MY_TITLE, namePanel.getClass(), false);
//		chooseApply(memoryMergePanel);
//		waitForMergeCompletion();
	}

	@Test
	public void testProgramTreeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("Modify Original Program");
				try {
					listing.createRootModule("Main Tree");
					listing.createRootModule("Tree Three");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				Listing listing = program.getListing();
				int transactionID = program.startTransaction("Modify Latest Program");
				try {
					ProgramModule root = listing.getRootModule("Main Tree");
					root.createFragment("frag_one");
					root.createModule("my module");
					listing.renameTree("Main Tree", "My Tree");
					listing.createRootModule("Another Main Tree");

					// rename Tree Three to Tree3_XXX
					listing.renameTree("Tree Three", "Tree3_XXX");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("Modify My Program");
				try {
					Listing listing = program.getListing();

					ProgramModule m = listing.getRootModule("Main Tree");

					ProgramFragment textFrag = listing.getFragment("Main Tree", ".text");
					// create a module
					m = m.createModule("my new module");
					// create a fragment under "my new module"
					ProgramFragment frag = m.createFragment("my fragment");
					try {
						frag.move(textFrag.getMinAddress(), textFrag.getMaxAddress());
					}
					catch (NotFoundException e1) {
						Assert.fail("Got NotFoundException!");
					}
					// rename tree to cause a conflict
					listing.renameTree("Main Tree", "My Main Tree");

					listing.renameTree("Tree Three", "MY TREE 3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(700, 650);
		Window window = mergeTool.getActiveWindow();

		selectButtonAndApply(MergeConstants.ORIGINAL_TITLE, window, false);// Use name "Main Tree", lose "My Main Tree"

		mtfGenerator.captureComponent(window);

		selectButtonAndApply(MergeConstants.LATEST_TITLE, window, true);// Use "Tree3_XXX", lose "MY TREE 3"
		waitForMergeCompletion();
	}

	@Test
	public void testDataTypeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					Category miscCat = dtm.createCategory(new CategoryPath("/MISC"));
					Structure s = new StructureDataType("Foo", 0);
					s.add(new ByteDataType());
					s.add(DataType.DEFAULT);
					s.add(new FloatDataType());
					miscCat.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();

					DataType dataType = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					Structure s = (Structure) dataType;
					s.replace(1, new ByteDataType(), 1);

					Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
					miscCat.setName("Category3");
					Category cat1 = dtm.createCategory(new CategoryPath("/Category1"));
					Category cat2 = cat1.createCategory("Category2");
					cat2.moveCategory(miscCat, monitor);

					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Error modifying Latest program.");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Error modifying Latest program.");
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();

					DataType dataType = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					dataType.setName("My_Foo");
					Structure s = (Structure) dataType;
					s.replace(1, new CharDataType(), 1);

					Category category = dtm.getCategory(new CategoryPath("/MISC"));
					category.setName("Category1");
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Error modifying My program.");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Error modifying My program.");
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(800, 550);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	@Test
	public void testCategoryConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();
					dtm.createCategory(new CategoryPath("/MISC"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();

					Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
					Category cat1 = dtm.createCategory(new CategoryPath("/Category1"));
					Category cat2 = cat1.createCategory("Category2");
					Category cat3 = cat2.createCategory("Category3");
					cat3.moveCategory(miscCat, monitor);

					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Error modifying Latest program.");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Error modifying Latest program.");
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					DataTypeManager dtm = program.getDataTypeManager();

					Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
					Category cat1 = dtm.createCategory(new CategoryPath("/Category1"));
					cat1.moveCategory(miscCat, monitor);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Error modifying My program.");
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(700, 450);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	@Test
	public void testRegConflict() throws Exception {
		final String regNameDR0 = "DR0";

		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					ProgramContext pc = program.getProgramContext();
					Register regDR0 = pc.getRegister(regNameDR0);

					setRegValue(pc, addr(program, "004010a0"), addr(program, "004010a3"), regDR0,
						0x1234L);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext pc = program.getProgramContext();
					Register regDR0 = pc.getRegister(regNameDR0);

					setRegValue(pc, addr(program, "004010a0"), addr(program, "004010a3"), regDR0,
						0x5L);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ProgramContext pc = program.getProgramContext();
					Register regDR0 = pc.getRegister(regNameDR0);

					pc.remove(addr(program, "004010a0"), addr(program, "004010a3"), regDR0);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1300, 850);
		goToListing("0x004010a0");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	@Test
	public void testListingMergeDescriptions() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createData(program, "0x0040e694", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					clear(program, "0x0040e694", "0x0040e695");
					createData(program, "0x0040e694", new ArrayDataType(new ByteDataType(), 2, 1));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					clear(program, "0x0040e694", "0x0040e695");
					createData(program, "0x0040e694", new ArrayDataType(new CharDataType(), 2, 1));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1200, 730);
		goToListing("0x0040e694");
		Window window = mergeTool.getActiveWindow();
		Image image = mtfGenerator.captureComponent(window);

		ProgramMergeManagerPlugin programMergeManagerPlugin =
			getPlugin(mergeTool, ProgramMergeManagerPlugin.class);
		assertNotNull(programMergeManagerPlugin);
		Object mergeManagerProvider = getInstanceField("provider", programMergeManagerPlugin);

		Point windowLocationOnScreen = window.getLocationOnScreen();

		ListingMergePanel listingMergePanel = mergeMgr.getListingMergePanel();

		// Main panel is ListingMergePanel.

		// Top of ListingMergePanel is a ConflictInfoPanel.
		Object topComp = getInstanceField("topComp", listingMergePanel);
		ConflictInfoPanel conflictInfoPanel = (ConflictInfoPanel) topComp;

		// Middle of ListingMergePanel is the listings.
		ListingPanel[] listingPanels =
			(ListingPanel[]) getInstanceField("listingPanels", listingMergePanel);
		TitledPanel[] titlePanels =
			(TitledPanel[]) getInstanceField("titlePanels", listingMergePanel);

		// Bottom of ListingMergePanel is the conflict panel (VariousChoicesPanel or VerticalChoicesPanel).
		Object bottomComp = getInstanceField("bottomComp", listingMergePanel);
		VariousChoicesPanel variousChoicesPanel = (VariousChoicesPanel) bottomComp;

		addConflictTypeDescription(windowLocationOnScreen, conflictInfoPanel);

		addAddressDescription(windowLocationOnScreen, conflictInfoPanel);

		addAddressRangeDescription(image, windowLocationOnScreen, conflictInfoPanel);

		addConflictNumberDescription(windowLocationOnScreen, conflictInfoPanel);

		addShowHeaderDescription(image, windowLocationOnScreen, titlePanels);

		addGreyListingDescription(image, windowLocationOnScreen, listingPanels);

		addLockDescription(image, windowLocationOnScreen, titlePanels);

		addConflictAreaDescription(windowLocationOnScreen, variousChoicesPanel);

		addConflictButtonDescription(window, windowLocationOnScreen, variousChoicesPanel);

		addUseForAllDescription(windowLocationOnScreen, variousChoicesPanel);

		addApplyDescription(image, windowLocationOnScreen, mergeManagerProvider);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	private void addLockDescription(Image image, Point windowLocationOnScreen,
			TitledPanel[] titlePanels) {
		@SuppressWarnings("unchecked")
		List<JComponent> titleComps0 =
			(List<JComponent>) getInstanceField("titleComps", titlePanels[0]);
		JComponent lockButton0 = null;
		for (JComponent jComponent : titleComps0) {
			if (jComponent.getToolTipText().equals("Lock/Unlock with other views")) {
				lockButton0 = jComponent;
			}
		}
		assertNotNull(lockButton0);
		@SuppressWarnings("unchecked")
		List<JComponent> titleComps3 =
			(List<JComponent>) getInstanceField("titleComps", titlePanels[3]);
		JComponent lockButton3 = null;
		for (JComponent jComponent : titleComps3) {
			if (jComponent.getToolTipText().equals("Lock/Unlock with other views")) {
				lockButton3 = jComponent;
			}
		}
		assertNotNull(lockButton3);
		Point lockButton0Location = lockButton0.getLocationOnScreen();
		Point lockButton3Location = lockButton3.getLocationOnScreen();
		int lock0X = lockButton0Location.x - windowLocationOnScreen.x;
		int lock0Y = lockButton0Location.y - windowLocationOnScreen.y;
		int lock3Y = lockButton3Location.y - windowLocationOnScreen.y;
		String description1 = "Each lock controls whether the associated program listing's";
		String description2 = "scrolling is synchronized with other locked listings.";
		int descriptionWidth1 = getDescriptionWidth(image, description1);
		int descriptionWidth2 = getDescriptionWidth(image, description2);
		int descriptionWidth = Math.max(descriptionWidth1, descriptionWidth2);
		int arrowTailX = lock0X - 60;
		int arrowHeadX = lock0X;
		int descriptionX = arrowTailX - 5 - descriptionWidth;
		int arrowTailY = (lock0Y + lock3Y) / 2;
		int arrowHead1Y = lock0Y + lockButton0.getHeight();
		int arrowHead2Y = lock3Y;
		int description1Y = arrowTailY - 10;
		int description2Y = arrowTailY + 10;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHead1Y), 8);
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHead2Y), 8);
		mtfGenerator.drawText(description1, Color.RED, new Point(descriptionX, description1Y),
			DESCRIPTION_FONT_SIZE);
		mtfGenerator.drawText(description2, Color.RED, new Point(descriptionX, description2Y),
			DESCRIPTION_FONT_SIZE);
	}

	private void addGreyListingDescription(Image image, Point windowLocationOnScreen,
			ListingPanel[] listingPanels) {
		Point listing0Location = listingPanels[0].getLocationOnScreen();
		int listingX = listing0Location.x - windowLocationOnScreen.x;
		int listingY = listing0Location.y - windowLocationOnScreen.y;
		String greyListingDescription = "Grey background indicates addresses for current conflict.";
		Dimension size = listingPanels[0].getSize();
		int descriptionX = listingX + (size.width / 3);
		int descriptionY = listingY + size.height - 20;
		mtfGenerator.drawText(greyListingDescription, Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addShowHeaderDescription(Image image, Point windowLocationOnScreen,
			TitledPanel[] titlePanels) {
		@SuppressWarnings("unchecked")
		List<JComponent> titleComps0 =
			(List<JComponent>) getInstanceField("titleComps", titlePanels[0]);
		JComponent showHeaderButton = null;
		for (JComponent jComponent : titleComps0) {
			if (jComponent.getToolTipText().equals("Toggle Format Header")) {
				showHeaderButton = jComponent;
			}
		}
		assertNotNull(showHeaderButton);
		Point buttonLocation = showHeaderButton.getLocationOnScreen();
		int buttonX = buttonLocation.x - windowLocationOnScreen.x;
		int buttonY =
			buttonLocation.y - windowLocationOnScreen.y + (showHeaderButton.getHeight() / 2);
		int arrowHeadX = buttonX - 5;
		int arrowTailX = buttonX - 35;
		String adjustFieldsDescription =
			"Lets you adjust the fields displayed in all four listings.";
		int descriptionWidth = getDescriptionWidth(image, adjustFieldsDescription);
		int descriptionX = buttonX - 40 - descriptionWidth;
		int arrowHeadY = buttonY;
		int arrowTailY = buttonY;
		int descriptionY = buttonY + 5;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText(adjustFieldsDescription, Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addConflictNumberDescription(Point windowLocationOnScreen,
			ConflictInfoPanel conflictInfoPanel) {
		JLabel westLabel = (JLabel) getInstanceField("westLabel", conflictInfoPanel);
		Point westLabelLocation = westLabel.getLocationOnScreen();
		Dimension size = westLabel.getSize();
		int westLabelX = westLabelLocation.x - windowLocationOnScreen.x;
		int conflictNumberX = westLabelX + (size.width / 4);
		int arrowHeadX = conflictNumberX;
		int arrowTailX = arrowHeadX + 40;
		int descriptionX = arrowTailX + 5;
		int westLabelY = westLabelLocation.y - windowLocationOnScreen.y + 5;
		int westLabelBottomY = westLabelY + size.height;
		int arrowHeadY = westLabelBottomY;
		int arrowTailY = westLabelBottomY + 15;
		int descriptionY = westLabelBottomY + 20;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowTailY), 0);
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowHeadX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText("Indicates which conflict you are resolving.", Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addAddressRangeDescription(Image image, Point windowLocationOnScreen,
			ConflictInfoPanel conflictInfoPanel) {
		JLabel eastLabel = (JLabel) getInstanceField("eastLabel", conflictInfoPanel);
		Point eastLabelLocation = eastLabel.getLocationOnScreen();
		Dimension size = eastLabel.getSize();
		String addressRangeDescription = "Indicates how many address ranges have conflicts.";
		int descriptionWidth = getDescriptionWidth(image, addressRangeDescription);
		int eastLabelX = eastLabelLocation.x - windowLocationOnScreen.x;
		int eastLabelMidX = eastLabelX + (size.width / 2);
		int arrowHeadX = eastLabelMidX;
		int descriptionX = eastLabelX + size.width - descriptionWidth;
		int eastLabelY = eastLabelLocation.y - windowLocationOnScreen.y + 5;
		int arrowHeadY = eastLabelY - 10;
		int arrowTailY = arrowHeadY - 30;
		int descriptionY = arrowTailY - 5;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowHeadX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText(addressRangeDescription, Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private int getDescriptionWidth(Image image, String description) {
		Graphics g = image.getGraphics();
		Font font = g.getFont();
		g.setFont(font.deriveFont(DESCRIPTION_FONT_SIZE));
		g.setColor(Color.RED);
		FontMetrics fontMetrics = g.getFontMetrics(font.deriveFont(DESCRIPTION_FONT_SIZE));
		int descriptionWidth = fontMetrics.stringWidth(description);
		return descriptionWidth;
	}

	private void addAddressDescription(Point windowLocationOnScreen,
			ConflictInfoPanel conflictInfoPanel) {
		JLabel westLabel = (JLabel) getInstanceField("westLabel", conflictInfoPanel);
		Point westLabelLocation = westLabel.getLocationOnScreen();
		Dimension preferredSize = westLabel.getPreferredSize();
		int westLabelX = westLabelLocation.x - windowLocationOnScreen.x;
		int westLabelRightX = westLabelX + preferredSize.width;
		int arrowHeadX = westLabelRightX + 10;
		int arrowTailX = arrowHeadX + 50;
		int descriptionX = arrowTailX + 10;
		int westLabelY = westLabelLocation.y - windowLocationOnScreen.y;
		int arrowY = westLabelY + 5;
		int descriptionY = arrowY;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowY),
			new Point(arrowHeadX, arrowY), 8);
		mtfGenerator.drawText("Indicates the address(es) in conflict.", Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addConflictTypeDescription(Point windowLocationOnScreen,
			ConflictInfoPanel conflictInfoPanel) {
		Point infoPanelLocation = conflictInfoPanel.getLocationOnScreen();
		TitledBorder border = (TitledBorder) conflictInfoPanel.getBorder();
		Dimension minimumSize = border.getMinimumSize(new JPanel());
		int width = minimumSize.width;
		int endTitleTextX = infoPanelLocation.x - windowLocationOnScreen.x + width;
		int arrowHeadX = endTitleTextX + 10;
		int arrowTailX = arrowHeadX + 50;
		int descriptionX = arrowTailX + 10;
		int endTitleTextY = infoPanelLocation.y - windowLocationOnScreen.y;
		int arrowTailY = endTitleTextY - 5;
		int arrowHeadY = endTitleTextY + 5;
		int descriptionY = endTitleTextY;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText("Type of conflict to resolve.", Color.RED,
			new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addConflictAreaDescription(Point windowLocationOnScreen,
			VariousChoicesPanel variousChoicesPanel) {
		Point variousChoicesLocation = variousChoicesPanel.getLocationOnScreen();
		int conflictAreaX = variousChoicesLocation.x - windowLocationOnScreen.x;
		int conflictAreaY = variousChoicesLocation.y - windowLocationOnScreen.y;
		mtfGenerator.drawText("Area indicating the specific information", Color.RED,
			new Point(conflictAreaX + 20, conflictAreaY + 40), DESCRIPTION_FONT_SIZE);
		mtfGenerator.drawText("for the current conflict(s) being resolved.", Color.RED,
			new Point(conflictAreaX + 20, conflictAreaY + 60), DESCRIPTION_FONT_SIZE);
	}

	private void addConflictButtonDescription(Window window, Point windowLocationOnScreen,
			VariousChoicesPanel variousChoicesPanel) {
		JPanel rowPanel = (JPanel) getInstanceField("rowPanel", variousChoicesPanel);
		Dimension rowPanelSize = rowPanel.getPreferredSize();
		Point rowPanelLocation = rowPanel.getLocationOnScreen();
		int rowPanelWidth = rowPanelSize.width;
		int rowPanelHeight = rowPanelSize.height;
		int radioButtonX = (window.getWidth() / 2) + (rowPanelWidth / 2) + 5;
		int radioButtonY = rowPanelLocation.y - windowLocationOnScreen.y + (rowPanelHeight / 2);
		int arrowHeadX = radioButtonX;
		int arrowTailX = radioButtonX + 40;
		int descriptionX = radioButtonX + 45;
		int arrowHeadY = radioButtonY;
		int arrowTailY = radioButtonY - 10;
		int description1Y = radioButtonY - 20;
		int description2Y = radioButtonY;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText("Radio buttons or check boxes to", Color.RED,
			new Point(descriptionX, description1Y), DESCRIPTION_FONT_SIZE);
		mtfGenerator.drawText("select for resolving the conflict(s).", Color.RED,
			new Point(descriptionX, description2Y), DESCRIPTION_FONT_SIZE);
	}

	private void addUseForAllDescription(Point windowLocationOnScreen,
			VariousChoicesPanel variousChoicesPanel) {
		JCheckBox useForAllCB = (JCheckBox) getInstanceField("useForAllCB", variousChoicesPanel);
		Point useForAllLocation = useForAllCB.getLocationOnScreen();
		Dimension useForAllSize = useForAllCB.getPreferredSize();
		int useForAllWidth = useForAllSize.width;
		int useForAllRightEdge = useForAllLocation.x - windowLocationOnScreen.x + useForAllWidth;
		int arrowHeadX = useForAllRightEdge;
		int arrowTailX = arrowHeadX + 50;
		int descriptionX = arrowTailX + 5;
		int useForAllY = useForAllLocation.y - windowLocationOnScreen.y;
		int checkBoxHeight = useForAllCB.getSize().height;
		int arrowY = useForAllY + (checkBoxHeight / 2);
		int descriptionY = useForAllY + 15;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowY),
			new Point(arrowHeadX, arrowY), 8);
		mtfGenerator.drawText(
			"Check this box to automatically make the same choice for all remaining conflicts like this one.",
			Color.RED, new Point(descriptionX, descriptionY), DESCRIPTION_FONT_SIZE);
	}

	private void addApplyDescription(Image image, Point windowLocationOnScreen,
			Object mergeManagerProvider) {
		JButton applyButton = (JButton) getInstanceField("applyButton", mergeManagerProvider);
		Point applyButtonLocation = applyButton.getLocationOnScreen();
		String description1 = "Select Apply after resolving the";
		String description2 = "conflict to continue with the merge.";
		int width1 = getDescriptionWidth(image, description1);
		int width2 = getDescriptionWidth(image, description2);
		int descriptionWidth = Math.max(width1, width2);
		int applyButtonX = applyButtonLocation.x - windowLocationOnScreen.x;
		int applyButtonY = applyButtonLocation.y - windowLocationOnScreen.y;
		int arrowHeadX = applyButtonX - 15;
		int arrowTailX = arrowHeadX - 65;
		int descriptionX = arrowTailX - 5 - descriptionWidth;
		int arrowTailY = applyButtonY + 10;
		int arrowHeadY = applyButtonY + 10;
		int description1Y = applyButtonY + 5;
		int description2Y = description1Y + 20;
		mtfGenerator.drawArrow(Color.RED, 2, new Point(arrowTailX, arrowTailY),
			new Point(arrowHeadX, arrowHeadY), 8);
		mtfGenerator.drawText(description1, Color.RED, new Point(descriptionX, description1Y),
			DESCRIPTION_FONT_SIZE);
		mtfGenerator.drawText(description2, Color.RED, new Point(descriptionX, description2Y),
			DESCRIPTION_FONT_SIZE);
	}

	@Test
	public void testCodeUnit2CharConflict() throws Exception {

		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Structure structure = new StructureDataType("SampleStructure", 0);
					structure.add(new ByteDataType());
					structure.add(new WordDataType());
					structure.add(new FloatDataType());

					clear(program, "0x0040e694", "0x0040e69b");
					createData(program, "0x0040e694", structure);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Structure structure = new StructureDataType("SampleStructure", 0);
					structure.add(new ByteDataType());
					structure.add(new CharDataType());
					structure.add(new CharDataType());
					structure.add(new FloatDataType());

					clear(program, "0x0040e694", "0x0040e69b");
					createData(program, "0x0040e694", structure);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Structure structure = new StructureDataType("SampleStructure", 0);
					structure.add(new ByteDataType());
					structure.add(new ArrayDataType(new CharDataType(), 2, 1));
					structure.add(new FloatDataType());

					clear(program, "0x0040e694", "0x0040e69b");
					createData(program, "0x0040e694", structure);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		openEachListingsData("0x0040e694");
		setToolSize(1200, 750);
		goToListing("0x0040e695");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	@Test
	public void testExternalAddConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("Library2", SourceType.USER_DEFINED);
					externalManager.addExtLocation(externalLibrary, "activate",
						addr(program, "77ba5f22"), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("Library1", SourceType.USER_DEFINED);
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "process",
							addr(program, "77ba5f22"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					function.addParameter(new ParameterImpl("value",
						new PointerDataType(new IntegerDataType()), program),
						SourceType.USER_DEFINED);
					function.addParameter(new ParameterImpl("type", new ByteDataType(), program),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1200, 680);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testExternalDataTypeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("Library1", SourceType.USER_DEFINED);
					externalManager.addExtLocation(externalLibrary, "activate",
						addr(program, "77ba5f22"), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("Library1", "activate");
					externalLocation.setDataType(new FloatDataType());

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("Library1", "activate");
					Function function = externalLocation.createFunction();
					function.addParameter(new ParameterImpl("value",
						new PointerDataType(new IntegerDataType()), program),
						SourceType.USER_DEFINED);
					function.addParameter(new ParameterImpl("type", new ByteDataType(), program),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1200, 800);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve External Data Type Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testExternalFunctionParametersConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("Library2", SourceType.USER_DEFINED);
					externalManager.addExtLocation(externalLibrary, "process",
						addr(program, "77ba5f22"), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("Library2", "process");
					Function function = externalLocation.createFunction();

					function.addParameter(
						new ParameterImpl(null, new Undefined2DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("Library2", "process");
					Function function = externalLocation.createFunction();

					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined4DataType(), program),
						SourceType.USER_DEFINED);
					function.addParameter(
						new ParameterImpl(null, new Undefined2DataType(), program),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		waitForPostedSwingRunnables();

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1300, 950);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Function Parameters Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testParameterMultiConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function = getFunction(program, "0x00401130");
					function.setReturnType(new PointerDataType(), SourceType.USER_DEFINED);
					Parameter parameter0 = function.getParameter(0);
					parameter0.setComment("Latest parameter 1 comment.");

					Parameter parameter1 = function.getParameter(1);
					parameter1.setName("value", SourceType.USER_DEFINED);
					parameter1.setComment("Latest parameter 2 comment.");

					Function function2 = getFunction(program, "0x00401240");
					Parameter parameter = function2.getParameter(0);
					parameter.setComment("Latest parameter 0 comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function = getFunction(program, "0x00401130");
					function.setReturnType(new FloatDataType(), SourceType.USER_DEFINED);
					Parameter parameter0 = function.getParameter(0);
					parameter0.setComment("My parameter 1 comment.");

					Parameter parameter1 = function.getParameter(1);
					parameter1.setName("type", SourceType.USER_DEFINED);
					parameter1.setComment("My parameter 2 comment.");

					Function function2 = getFunction(program, "0x00401240");
					Parameter parameter = function2.getParameter(0);
					parameter.setComment("My parameter 0 comment.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		chooseButtonAndApply("Resolve Function Return Conflict", LATEST_BUTTON_NAME);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });

		setToolSize(1300, 950);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST, KEEP_LATEST });
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();
	}

	@Test
	public void testFunctionOverlapConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x00401130");
					removeFunction(program, "0x00401240");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					AddressSet body =
						new AddressSet(addr(program, "0x00401130"), addr(program, "0x00401264"));
					functionManager.createFunction(null, addr(program, "0x00401130"), body,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					FunctionManager functionManager = program.getFunctionManager();
					AddressSet body2 =
						new AddressSet(addr(program, "0x00401240"), addr(program, "0x00401264"));
					functionManager.createFunction(null, addr(program, "0x00401240"), body2,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1300, 950);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseVariousOptionsForConflictType("Resolve Function Overlap Conflict",
			new int[] { KEEP_LATEST });
		waitForMergeCompletion();
	}

	@Test
	public void testFunctionRemoveVsChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x00401130");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x00401130");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 950);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		verticalChooseFunction("0x00401130", KEEP_LATEST);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolRemoveVsChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createLabel(addr(program, "0x0040156c"), "DDD", SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getGlobalSymbol("DDD", addr(program, "0x0040156c"));
					symbol.delete();
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getGlobalSymbol("DDD", addr(program, "0x0040156c"));
					Namespace namespace = getFunction(program, "0x00401130");
					symbol.setNamespace(namespace);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x0040113a");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Symbol Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolRenameWithScopeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x0040156c"), "AAA", namespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getGlobalSymbol("AAA", addr(program, "0x0040156c"));
					symbol.setName("ME", SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getGlobalSymbol("AAA", addr(program, "0x0040156c"));
					symbol.setNameAndNamespace("ME", program.getGlobalNamespace(),
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x0040113c");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Symbol Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolAddressConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					symtab.createLabel(addr(program, "0x0040156c"), "BBB", namespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x0040156c"), "BBB", namespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x0040113c");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Symbol Conflict", REMOVE_CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolPrimaryConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x0040156c"), "Foo", namespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x0040156c"), "Bar", namespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x0040113c");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Symbol Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolNamespaceKept() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "FirstNamespace",
						SourceType.USER_DEFINED);
					symtab.createNameSpace(program.getGlobalNamespace(), "SecondNamespace",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol firstNsSym =
						getUniqueSymbol(program, "FirstNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(firstNsSym);
					Namespace secondNamespace = (Namespace) getUniqueSymbol(program,
						"SecondNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x0040156c"), "soccer", secondNamespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol secondNsSym =
						getUniqueSymbol(program, "SecondNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(secondNsSym);
					Namespace firstNamespace = (Namespace) getUniqueSymbol(program,
						"FirstNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x00401140"), "football", firstNamespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForReadTextDialog("Symbol Merge Information",
			"The following namespaces were not removed", 4000, false);

		mtfGenerator.captureDialog();

		waitForReadTextDialog("Symbol Merge Information",
			"The following namespaces were not removed", 4000, true);
		waitForMergeCompletion();
	}

	@Test
	public void testSymbolConflictAutoRenamed() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x0040114a"), "YOU", namespace,
						SourceType.USER_DEFINED);
					createGlobalSymbol(program, "0x0040156c", "ME");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace namespace = getFunction(program, "0x00401130");
					symtab.createLabel(addr(program, "0x00401150"), "YOU", namespace,
						SourceType.USER_DEFINED);
					createGlobalSymbol(program, "0x00401140", "ME");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000, false);

		mtfGenerator.captureDialog();

		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000, true);
		waitForMergeCompletion();
	}

	@Test
	public void testEquateConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x00402e5f");
					try {
						equateTab.createEquate("01", 1).addReference(addr, 0);
					}
					catch (DuplicateNameException e) {
						Assert.fail(e.getMessage());
					}
					catch (InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					changeEquate(program, "0x00402e5f", 0, 1L, "PEAR");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					changeEquate(program, "0x00402e5f", 0, 1L, "ORANGE");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1200, 750);
		goToListing("0x00402e5f");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Equate Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testUserDefinedUseForAllConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					PropertyMapManager pmm = program.getUsrPropertyManager();
					IntPropertyMap pm = pmm.createIntPropertyMap("Space");
					pm.add(addr(program, "0x00401002"), 1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					PropertyMapManager pmm = program.getUsrPropertyManager();
					IntPropertyMap pm = pmm.getIntPropertyMap("Space");
					pm.add(addr(program, "0x00401002"), 3);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					PropertyMapManager pmm = program.getUsrPropertyManager();
					IntPropertyMap pm = pmm.getIntPropertyMap("Space");
					pm.add(addr(program, "0x00401002"), 4);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1000, 700);
		goToListing("0x00401002");
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve User Defined Property Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testExternalRefConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					ExternalManager externalManager = program.getExternalManager();
					externalManager.addExtLocation("KERNEL32.DLL", "allocate", null,
						SourceType.USER_DEFINED);
					externalManager.addExtLocation("KERNEL32.DLL", "stuff", null,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					refs = refMgr.getReferencesFrom(addr(program, "0x0040b044"), 0);
					assertEquals(1, refs.length);
					Reference reference = refs[0];
					Address fromAddress = reference.getFromAddress();
					int operandIndex = reference.getOperandIndex();

					refMgr.delete(refs[0]);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("KERNEL32.DLL", "allocate");
					refMgr.addExternalReference(fromAddress, operandIndex, externalLocation,
						SourceType.USER_DEFINED, RefType.DATA);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					refs = refMgr.getReferencesFrom(addr(program, "0x0040b044"), 0);
					assertEquals(1, refs.length);
					Reference reference = refs[0];
					Address fromAddress = reference.getFromAddress();
					int operandIndex = reference.getOperandIndex();

					refMgr.delete(refs[0]);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("KERNEL32.DLL", "stuff");
					refMgr.addExternalReference(fromAddress, operandIndex, externalLocation,
						SourceType.USER_DEFINED, RefType.DATA);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x0040b044");
		scrollHorizontal(45);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testRefRegStackConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					ProgramContext pc = program.getProgramContext();
					Register regESI = pc.getRegister("ESI");
					refMgr.addRegisterReference(addr(program, "0x004018e4"), 0, regESI,
						RefType.READ, SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x004018e4"), 0, -8, RefType.READ,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1000, 700);
		goToListing("0x004018e4");
		scrollHorizontal(30);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testMemRefConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					refs = refMgr.getReferencesFrom(addr(program, "0x00401eca"), 1);
					assertEquals(1, refs.length);
					Reference reference = refs[0];
					Address fromAddress = reference.getFromAddress();
					Address toAddress = reference.getToAddress();
					int operandIndex = reference.getOperandIndex();

					refMgr.delete(refs[0]);

					refMgr.addMemoryReference(fromAddress, toAddress, RefType.READ_WRITE,
						SourceType.USER_DEFINED, operandIndex);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					refs = refMgr.getReferencesFrom(addr(program, "0x00401eca"), 1);
					assertEquals(1, refs.length);
					Reference reference = refs[0];
					Address fromAddress = reference.getFromAddress();
					Address toAddress = reference.getToAddress();
					int operandIndex = reference.getOperandIndex();

					refMgr.delete(refs[0]);

					refMgr.addMemoryReference(fromAddress, toAddress, RefType.READ,
						SourceType.USER_DEFINED, operandIndex);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 700);
		goToListing("0x00401f05");
		scrollHorizontal(30);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testRefTypeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x004017db"),
						addr(program, "0x00401953"), RefType.READ, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x004017db"),
						addr(program, "0x0040cbc8"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x004017db"),
						addr(program, "0x004018bc"), RefType.READ_IND, SourceType.USER_DEFINED, 1);
					refMgr.addExternalReference(addr(program, "0x00401810"), "USER32.DLL",
						"getMessage", addr(program, "0x1001a11"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addExternalReference(addr(program, "0x004017db"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 1, RefType.DATA);
					refMgr.addMemoryReference(addr(program, "0x00401810"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x00401810"),
						addr(program, "0x100190b"), RefType.DATA, SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x00401810"),
						addr(program, "0x100191f"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 750);
		goToListing("0x004017db");
		scrollHorizontal(30);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON_NAME);
		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testBmNoteBothAddConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x00401131");
					bookMgr.setBookmark(addr, BookmarkType.NOTE, "Test", "Call to print.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x00401131");
					bookMgr.setBookmark(addr, BookmarkType.NOTE, "Calls", "invoke print function");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME, VerticalChoicesPanel.class, false);
		setToolSize(1100, 750);
		goToListing("0x0040156c");

		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseApply();
		waitForMergeCompletion();
	}

	@Test
	public void testBmRemoveVsChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x004010a0");
					bookMgr.setBookmark(addr, BookmarkType.ANALYSIS, "Found Code",
						"Found code from operand reference");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x004010a0");
					bookMgr.setBookmark(addr, BookmarkType.ANALYSIS, "Found Code",
						"Latest bookmark @ 0x004010a0");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					BookmarkManager bookMgr = program.getBookmarkManager();
					Address addr = addr(program, "0x004010a0");
					bookMgr.removeBookmarks(new AddressSet(addr), TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME, VerticalChoicesPanel.class, false);
		setToolSize(1100, 750);
		goToListing("0x004010a0");

		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseApply();
		waitForMergeCompletion();
	}

	@Test
	public void testCommentRemoveVsChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT, "Before the code unit.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT, null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT, "This is a changed pre-comment.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME, VerticalChoicesPanel.class, false);
		setToolSize(1100, 750);
		goToListing("0x0040156c");
		scrollHorizontal(30);

		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseApply();
		waitForMergeCompletion();
	}

	@Test
	public void testCommentChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT, "This is a simple comment for example.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT, "This is a simple comment for example.\n" +
						"I added some more to this comment to make it multiple lines.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					CodeUnit cu;
					cu = listing.getCodeUnitAt(addr(program, "0x0040156c"));
					cu.setComment(CodeUnit.PRE_COMMENT,
						"Changed this to a multiple line comment.\n" +
							"It was necessary for demonstration purposes.");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		chooseVerticalCheckBoxes(new String[] { LATEST_CHECK_BOX_NAME, CHECKED_OUT_CHECK_BOX_NAME },
			false);
		setToolSize(1100, 750);
		goToListing("0x0040156c");
		scrollHorizontal(30);

		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseApply();
		waitForMergeCompletion();
	}

	@Test
	public void testExternalProgramChangeConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//advapi32.dll",
						true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//foo.dll", true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//bar.dll", true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(600, 400);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve External Program Name Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testExternalProgramRemoveConflict() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//advapi32.dll",
						true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeExternalLibrary(program, "ADVAPI32.DLL");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getExternalManager().setExternalPath("ADVAPI32.DLL", "//my.dll", true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(600, 400);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply("Resolve External Program Name Conflict", LATEST_BUTTON_NAME);
		waitForMergeCompletion();
	}

	@Test
	public void testProperyListConflict() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Options list = program.getOptions("Analysis Disassembly");
					list.setBoolean("Mark Bad Disassembly  ", true);
					list.setBoolean("Mark Bad Disassembly ", true);
					list.setBoolean("Mark Bad Disassembly", true);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Options list = program.getOptions("Analysis Disassembly");
					list.setBoolean("Mark Bad Disassembly  ", false);
					list.setBoolean("Mark Bad Disassembly ", false);
					list.setBoolean("Mark Bad Disassembly", false);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(600, 550);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		chooseButtonAndApply(MergeConstants.MY_TITLE, window);
		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();
	}

	@Test
	public void testDataTypeSourceConflict() throws Exception {

		FrontEndTool frontEndTool = env.showFrontEndTool();
		DomainFolder rootFolder = frontEndTool.getProject().getProjectData().getRootFolder();
		TaskMonitor dummyMonitor = TaskMonitorAdapter.DUMMY_MONITOR;
		DomainFile myTestArchiveDF =
			env.restoreDataTypeArchive("MyTestArchive.gdt", rootFolder);
		final DataTypeArchive myTestArchive =
			(DataTypeArchiveDB) myTestArchiveDF.getDomainObject(this, true, false,
				TaskMonitorAdapter.DUMMY_MONITOR);

		final CategoryPath sourceCatPath = new CategoryPath("/Category1/Category2/Category5");
		final DataType floatStruct =
			myTestArchive.getDataTypeManager().getDataType(sourceCatPath, "FloatStruct");
		assertNotNull(floatStruct);

		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Category rootCat = dtm.getRootCategory();
				try {
					// Add the structure to the root category.
					rootCat.addDataType(floatStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				try {
					SourceArchive sourceArchive =
						dtm.getSourceArchive(myTestArchive.getDataTypeManager().getUniversalID());
					sourceArchive.setName("TestArchiveOne");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				SourceArchive sourceArchive =
					dtm.getSourceArchive(myTestArchive.getDataTypeManager().getUniversalID());
				assertNotNull(sourceArchive);
				assertEquals("TestArchiveOne", sourceArchive.getName());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				try {
					SourceArchive sourceArchive =
						dtm.getSourceArchive(myTestArchive.getDataTypeManager().getUniversalID());
					sourceArchive.setName("TestArchiveTwo");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				SourceArchive sourceArchive =
					dtm.getSourceArchive(myTestArchive.getDataTypeManager().getUniversalID());
				assertNotNull(sourceArchive);
				assertEquals("TestArchiveTwo", sourceArchive.getName());
			}
		});

		executeMerge(ASK_USER);

		waitForPrompting();
		setToolSize(1100, 450);
		Window window = mergeTool.getActiveWindow();
		mtfGenerator.captureComponent(window);

		chooseButtonAndApply(MergeConstants.LATEST_TITLE, window);
		waitForMergeCompletion();

		myTestArchive.release(this);
		myTestArchiveDF = null;
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setToolSize(final int width, final int height) throws Exception {
		runSwing(() -> mergeTool.setSize(width, height));
		waitForPostedSwingRunnables();
		sleep(500);
	}

	private void waitForCompletion(Window window) throws Exception {
		while (!mergeMgr.processingCompleted()) {
			Thread.sleep(300);
		}

		if (window != null) {
			int numWaits = 0;
			int waitTime = 250;
			while (window.isVisible() && (numWaits * waitTime) < MAX_MERGE_TIMEOUT) {
				numWaits++;
				Thread.sleep(waitTime);
			}
		}
	}

	private void selectButtonAndApply(String text, Window window, boolean doWait) throws Exception {
		final JRadioButton rb = (JRadioButton) findButton(window, text);
		assertNotNull(rb);
		SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);

		pressButton(applyButton);
		waitForPostedSwingRunnables();
		resultProgram.flushEvents();
		if (doWait) {
			waitForCompletion(window);
		}
		else {
			// wait until the panel has been reset
			while (applyButton.isEnabled() && rb.isVisible()) {
				Thread.sleep(250);
			}
			Thread.sleep(500);
		}
	}

	private void chooseButtonAndApply(String text, Window window) throws Exception {
		selectButtonAndApply(text, window, false);
	}

	private AbstractButton findButton(Container container, String text) {
		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton && element.isVisible()) &&
				((AbstractButton) element).getText().indexOf(text) >= 0) {
				return (AbstractButton) element;
			}
			else if ((element instanceof Container) && element.isVisible()) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	private void removeExternalLibrary(Program program, String libName) {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
		while (iter.hasNext()) {
			ExternalLocation loc = iter.next();
			if (!((ExternalManagerDB) extMgr).removeExternalLocation(
				loc.getExternalSpaceAddress())) {
				Assert.fail("Couldn't remove external location for library " + libName);
			}
		}
		if (!extMgr.removeExternalLibrary(libName)) {
			Assert.fail("Couldn't remove external library " + libName);
		}
	}

	public void goToListing(final String address) {
		runSwing(() -> {
			ListingMergePanel listingMergePanel = mergeMgr.getListingMergePanel();
			listingMergePanel.goTo(addr(address));
		});
		waitForPostedSwingRunnables();
	}

	public void openEachListingsData(final String address) {
		runSwing(() -> {
			ListingMergePanel listingMergePanel = mergeMgr.getListingMergePanel();
			ListingPanel[] listingPanels =
				(ListingPanel[]) TestUtils.getInstanceField("listingPanels", listingMergePanel);
			for (int i = 0; i < listingPanels.length; i++) {
				ListingPanel listingPanel = listingPanels[i];
				Program program = mergeMgr.getProgram(i);
				Data data = program.getListing().getDataAt(addr(program, address));
				listingPanel.getListingModel().openData(data);
			}
		});
		waitForPostedSwingRunnables();
	}

	protected void chooseApply(Container mergePanel) throws Exception {
		waitForApply(true);
		Window window = windowForComponent(mergePanel);
		assertNotNull(window);
		pressButtonByText(window, "Apply");
		waitForPostedSwingRunnables();
		waitForApply(false);
	}

	private void setRegValue(ProgramContext pc, Address start, Address end, Register reg,
			long value) throws ContextChangeException {
		BigInteger bi = BigInteger.valueOf(value);
		pc.setValue(reg, start, end, bi);
	}

	/**
	 * Changes the function's parameter indicated by index to be a register
	 * parameter with the indicated register.
	 * @param func the function
	 * @param index the index of an existing parameter
	 * @param reg the new register for this parameter
	 */
	protected void changeToRegisterParameter(Function func, int index, Register reg) {
		Parameter p = func.getParameter(index);
		String name = p.getName();
		DataType dt = p.getDataType();
		String comment = p.getComment();
		func.removeParameter(index);
		AddRegisterParameterCommand cmd =
			new AddRegisterParameterCommand(func, reg, name, dt, index, SourceType.USER_DEFINED);
		cmd.applyTo(func.getProgram());
		p = func.getParameter(index);
		if (!isDefaultParamName(name)) {
			try {
				p.setName(name, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}
			catch (InvalidInputException e) {
				Assert.fail(e.getMessage());
			}
		}
		if (comment != null) {
			p.setComment(comment);
		}
	}

	/**
	 * @param name the parameter name
	 * @return true if name is null or a default parameter name.
	 */
	private boolean isDefaultParamName(String name) {
		if (name == null) {
			return true;
		}
		if (name.startsWith(Function.DEFAULT_PARAM_PREFIX)) {
			String num = name.substring(Function.DEFAULT_PARAM_PREFIX.length());
			try {
				Integer.parseInt(num);
				return true;
			}
			catch (NumberFormatException e1) {
				// Fall thru to false case.
			}
		}
		return false;
	}

	protected void changeEquate(ProgramDB program, String address, int opIndex, long value,
			String newName) {
		EquateTable equateTab = program.getEquateTable();
		Address addr = addr(program, address);
		Equate oldEquate = equateTab.getEquate(addr, opIndex, value);
		if (oldEquate.getName().equals(newName)) {
			Assert.fail(
				"Equate '" + oldEquate.getName() + "' already exists with value=" + value + ".");
		}
		oldEquate.removeReference(addr, opIndex);
		try {
			Equate newEquate = equateTab.getEquate(newName);
			if (newEquate == null) {
				newEquate = equateTab.createEquate(newName, value);
			}
			if (newEquate.getValue() != value) {
				Assert.fail("Can't create equate '" + newEquate.getName() + "' with value=" +
					value + ". It already exists with value=" + newEquate.getValue() + ".");
			}
			newEquate.addReference(addr, opIndex);
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	private void scrollHorizontal(final int percent) {
		runSwing(() -> {
			ListingMergePanel listingMergePanel = mergeMgr.getListingMergePanel();
			ListingPanel[] listingPanels =
				(ListingPanel[]) TestUtils.getInstanceField("listingPanels", listingMergePanel);
			ListingPanel latestPanel = listingPanels[1];
			IndexedScrollPane latestScroller =
				(IndexedScrollPane) TestUtils.getInstanceField("scroller", latestPanel);
			JScrollPane scrollPane =
				(JScrollPane) TestUtils.getInstanceField("scrollPane", latestScroller);
			JScrollBar horizontalScrollBar = scrollPane.getHorizontalScrollBar();
			horizontalScrollBar.setValue(
				(horizontalScrollBar.getMinimum() + horizontalScrollBar.getMaximum() -
					horizontalScrollBar.getVisibleAmount()) * percent / 100);
		});
		waitForPostedSwingRunnables();
	}
}
