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

import static org.junit.Assert.assertNotNull;

import java.awt.*;
import java.awt.geom.GeneralPath;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToolBarData;
import docking.framework.ApplicationInformationDisplayFactory;
import docking.options.editor.OptionsDialog;
import docking.tool.ToolConstants;
import docking.widgets.dialogs.SettingsDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.GTree;
import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import generic.util.image.ImageUtils;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.analysis.AnalysisOptionsDialog;
import ghidra.app.plugin.core.bookmark.CreateBookmarkDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.comments.CommentsDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.AddressFieldFactory;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.listingpanel.MarginProvider;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.ToolUtils;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public abstract class AbstractScreenShotGenerator extends AbstractGhidraHeadedIntegrationTest {

	static {
		System.setProperty("user.name", "User-1");
	}

	protected static final String SAVE_CREATED_IMAGE_FILE_KEY =
		"ScreenShotGenerator.save.created.image";
	protected static final boolean SAVE_CREATED_IMAGE_FILE = Boolean.parseBoolean(
		System.getProperty(SAVE_CREATED_IMAGE_FILE_KEY, Boolean.FALSE.toString()));

	protected static final String NEW_FILENAME_SUFFIX_KEY = "ScreenShotGenerator.filename.suffix";
	protected static final String DEFAULT_FILENAME_SUFFIX = "";// default is to overwrite existing file
	protected static final String NEW_FILENAME_SUFFIX =
		System.getProperty(NEW_FILENAME_SUFFIX_KEY, DEFAULT_FILENAME_SUFFIX);

	protected static final int DIALOG_HEADER_HEIGHT = 22;

	public PluginTool tool;
	public TestEnv env;
	public Program program;
	public Image image;

	public AbstractScreenShotGenerator() {
		super();

		// this prevents test tool from appearing in the UI
		setInstanceField("allowTestTools", ToolUtils.class, Boolean.FALSE);
		setDockIcon();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		prepareTool();

		runSwing(() -> tool.getToolFrame().setBounds(new Rectangle(400, 400, 1200, 600)));
		waitForPostedSwingRunnables();

		loadProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	public void prepareTool() {
		tool = env.launchDefaultTool();
	}

	public void loadProgram() throws Exception {
		loadProgram("WinHelloCPP.exe");

		ResourceFile file = TestEnv.findProvidedDataTypeArchive("windows_vs12_32.gdt");
		DataTypeManagerService dtm = tool.getService(DataTypeManagerService.class);
		dtm.openArchive(file.getFile(false), false);
	}

	public void closeNonProgramArchives() {
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dtms = service.getDataTypeManagers();
		for (DataTypeManager dtm : dtms) {
			if (dtm instanceof BuiltInDataTypeManager || dtm instanceof ProgramDataTypeManager) {
				continue;
			}

			service.closeArchive(dtm);
		}
	}

	public Program loadProgram(final String programName) {
		runSwing(() -> {
			program = env.getProgram(programName);
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});
		return program;
	}

	public void exit() {
		System.exit(0);

	}

	public void setUser(String userName) {
		System.setProperty("user.name", userName);
	}

	protected void setDockIcon() {
		if (Taskbar.isTaskbarSupported()) {
			Taskbar taskbar = Taskbar.getTaskbar();
			if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
				taskbar.setIconImage(ApplicationInformationDisplayFactory.getLargestWindowIcon());
			}
		}
	}

	public Address addr(long value) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
	}

	public void setToolSize(final int width, final int height) {
		runSwing(() -> tool.getToolFrame().setSize(width, height));

		// TODO - hack; there must be a better way to wait for the window to update after a resize
		waitForSwing();
		sleep(250);
		waitForSwing();
	}

	public void setWindowSize(final Window window, final int width, final int height) {
		runSwing(() -> window.setSize(width, height));
		waitForSwing();
	}

	public void performAction(String actionName, String owner, boolean wait) {
		ComponentProvider componentProvider = getProvider(CodeViewerProvider.class);
		performAction(actionName, owner, componentProvider, wait);
	}

	public void performDialogAction(String actionName, boolean wait) {
		DialogComponentProvider dialog = getDialog();
		Set<DockingActionIf> actions = dialog.getActions();
		for (DockingActionIf action : actions) {
			if (action.getName().equals(actionName)) {
				performDialogAction(action, dialog, wait);
				return;
			}
		}
	}

	public void performAction(String actionName, String owner, ComponentProvider contextProvider,
			boolean wait) {
		DockingActionIf action = getAction(tool, owner, actionName);
		performAction(action, contextProvider, wait);
	}

	public void showOptions(final String optionsCategoryName) {
		performAction("Edit Options", ToolConstants.TOOL_OWNER, false);
		final OptionsDialog dialog = (OptionsDialog) getDialog();
		runSwing(() -> dialog.displayCategory(optionsCategoryName, null));

		Object optionsPanel = getInstanceField("panel", dialog);
		GTree tree = (GTree) getInstanceField("gTree", optionsPanel);
		waitForTree(tree);
		waitForSwing();
	}

	public void showProgramOptions(final String optionsCategoryName) {
		performAction("Program Options", "ProgramManagerPlugin", false);
		final OptionsDialog dialog = (OptionsDialog) getDialog();
		runSwing(() -> dialog.displayCategory(optionsCategoryName, null));

		Object optionsPanel = getInstanceField("panel", dialog);
		GTree tree = (GTree) getInstanceField("gTree", optionsPanel);
		waitForTree(tree);
		waitForSwing();
	}

	public Rectangle getCursorBounds() {
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		return fieldPanel.getCursorBounds();
	}

	public void pressOkOnDialog() {
		pressButtonOnDialog("OK");
	}

	public void pressButtonOnDialog(String buttonText) {
		waitForPostedSwingRunnables();
		DialogComponentProvider dialog = getDialog();
		pressButtonByText(dialog, buttonText);
	}

	public void captureIsolatedComponent(final JComponent component, final int width,
			final int height) {
		waitForPostedSwingRunnables();
		runSwing(() -> {
			JDialog dialog = new JDialog();
			dialog.getContentPane().setLayout(new BorderLayout());
			dialog.getContentPane().add(component, BorderLayout.CENTER);
			dialog.setSize(width, height + DIALOG_HEADER_HEIGHT);
			dialog.setVisible(true);

		});

		waitForSwing();

		runSwing(() -> generateImage(component));
	}

	public Image captureComponent(final Component component) {
		waitForSwing();
		runSwing(() -> {
			paintFix(tool.getToolFrame());
			generateImage(component);
		});
		return image;
	}

	/**
	 * The same as {@link GhidraScreenShotGenerator#captureIsolatedProvider(Class, int, int)}
	 * except this method will also capture the containing window.
	 * 
	 * @param clazz the provider class 
	 * @param width the width of the capture
	 * @param height the height of the capture
	 */
	public void captureIsolatedProviderWindow(final Class<? extends ComponentProvider> clazz,
			final int width, final int height) {
		waitForSwing();
		final ComponentProvider provider = tool.getWindowManager().getComponentProvider(clazz);
		if (provider == null) {
			Assert.fail("Could not find provider--is it installed?: " + clazz.getSimpleName());
		}

		moveProviderToItsOwnWindow(provider);

		final AtomicReference<Window> ref = new AtomicReference<>();
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException("Could not find window for " +
					"provider--is it showing?: " + provider.getName());
			}

			window.setSize(new Dimension(width, height));
			ref.set(window);
		});

		waitForSwing();
		captureWindow(ref.get());
	}

	public void captureIsolatedProvider(final Class<? extends ComponentProvider> clazz,
			final int width, final int height) {
		waitForSwing();
		final ComponentProvider provider = tool.getWindowManager().getComponentProvider(clazz);
		if (provider == null) {
			Assert.fail("Could not find provider--is it installed?: " + clazz.getSimpleName());
		}

		captureIsolatedProvider(provider, width, height);
	}

	public void captureIsolatedProvider(final ComponentProvider provider, final int width,
			final int height) {
		waitForSwing();

		moveProviderToItsOwnWindow(provider);

		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException("Could not find window for " +
					"provider--is it showing?: " + provider.getName());
			}

			window.setSize(new Dimension(width, height));
			window.toFront();
			provider.getComponent().requestFocus();
			paintFix(window);
		});

		waitForSwing();
		captureProvider(provider);
	}

	public void moveProviderToFront(final ComponentProvider provider, int width, int height) {

		moveProviderToItsOwnWindow(provider, width, height);
		waitForSwing();

		runSwing(() -> {
			Window window = windowForComponent(provider.getComponent());
			window.toFront();
		});

	}

	public void moveProviderToFront(final ComponentProvider provider) {

		moveProviderToItsOwnWindow(provider);
		waitForSwing();

		runSwing(() -> {
			Window window = windowForComponent(provider.getComponent());
			window.toFront();
		});

	}

	public void moveWindowUp(final Window window, final int yOffset) {
		runSwing(() -> {
			Point loc = window.getLocation();
			loc.y -= yOffset;
			window.setLocation(loc);
		});
	}

	public Window moveProviderToItsOwnWindow(final ComponentProvider provider) {
		DockingWindowManager dwm = tool.getWindowManager();
		Window w = DockingWindowManagerTestUtils.moveProviderToWindow(dwm, provider);
		waitForSwing();
		return w;
	}

	public Window moveProviderToItsOwnWindow(final ComponentProvider provider, final int width,
			final int height) {

		Window window = moveProviderToItsOwnWindow(provider);
		assertNotNull(window);

		runSwing(() -> {
			window.setSize(new Dimension(width, height));
		});
		return window;
	}

	public DockableComponent getDockableComponent(ComponentProvider provider) {
		return DockingWindowManagerTestUtils.getDockableComponent(tool.getWindowManager(),
			provider);
	}

	public void moveProvider(final ComponentProvider movee, final ComponentProvider relativeTo,
			final WindowPosition position) {

		DockingWindowManagerTestUtils.moveProvider(tool.getWindowManager(), movee, relativeTo,
			position);
	}

	public void captureMenu() {
		Set<Window> allWindows = getAllWindows();
		for (Window window : allWindows) {
			if (window.getClass().getSimpleName().equals("HeavyWeightWindow")) {
				captureComponent(window);
			}
		}
		drawBorder(Color.BLACK);
	}

	public JPopupMenu getPopupMenu() {
		Set<Window> allWindows = getAllWindows();
		for (Window window : allWindows) {
			if (window.getClass().getSimpleName().equals("HeavyWeightWindow")) {
				return findComponent(window, JPopupMenu.class);
			}
		}
		return null;
	}

	public void captureProvider(Class<? extends ComponentProvider> clazz) {
		waitForPostedSwingRunnables();
		runSwing(() -> {
			ComponentProvider provider = tool.getWindowManager().getComponentProvider(clazz);
			DockableComponent dc = getDockableComponent(provider);
			generateImage(dc);
		});
		waitForPostedSwingRunnables();
	}

	public void captureProvider(final ComponentProvider provider) {
		waitForPostedSwingRunnables();
		runSwing(() -> {
			DockableComponent dc = getDockableComponent(provider);
			generateImage(dc);
		});
		waitForPostedSwingRunnables();
	}

	public void captureProvider(final String name) {
		waitForPostedSwingRunnables();
		runSwing(() -> {
			ComponentProvider provider = tool.getWindowManager().getComponentProvider(name);
			DockableComponent dc = getDockableComponent(provider);
			generateImage(dc);
		});
		waitForPostedSwingRunnables();
	}

	/**
	 * Captures the provider by using a screen shot and not by painting the provider directly 
	 * (as does {@link #captureProvider(ComponentProvider)}).  Use this method if you need to
	 * capture the provider along with any popup windows.
	 * 
	 * @param provider the provider
	 */
	public void captureProviderWithScreenShot(ComponentProvider provider) {
		captureProviderWindow(provider);

		DockableComponent dockableComponent = getDockableComponent(provider);
		Rectangle bounds = dockableComponent.getBounds();

		// We now have a full capture of the window, but we only want the provider.  So, crop
		// out the provider.  To do this, we have to move the bounds of the provider from its
		// parent to that of the window.
		Point p = bounds.getLocation();
		Window window = SwingUtilities.windowForComponent(dockableComponent);
		Point newPoint = SwingUtilities.convertPoint(dockableComponent.getParent(), p, window);
		bounds.setLocation(newPoint);
		crop(bounds);
	}

	/**
	 * Captures the window, including decorations.  This will use a {@link Robot} to create a 
	 * screen capture, which has the effect of getting all items within the window bounds.  This
	 * method is needed if you wish to capture child windows, like popups/hovers.
	 * 
	 * <P>Other capture methods will not use the screen capture mechanism, but rather will 
	 * directly render the given component.  In this case, subordinate windows will not be 
	 * captured.  For example, see {@link #captureProvider(Class)}.
	 * 
	 * @param name the provider's name
	 */
	public void captureProviderWindow(String name) {
		waitForPostedSwingRunnables();
		ComponentProvider provider = tool.getWindowManager().getComponentProvider(name);
		captureProviderWindow(provider);
	}

	/**
	 * Captures the window, including decorations.  This will use a {@link Robot} to create a 
	 * screen capture, which has the effect of getting all items within the window bounds.  This
	 * method is needed if you wish to capture child windows, like popups/hovers.
	 * 
	 * <P>Other capture methods will not use the screen capture mechanism, but rather will 
	 * directly render the given component.  In this case, subordinate windows will not be 
	 * captured.  For example, see {@link #captureProvider(Class)}.
	 * 
	 * @param clazz the provider's class
	 */
	public void captureProviderWindow(Class<? extends ComponentProvider> clazz) {
		ComponentProvider provider = waitForComponentProvider(clazz);
		captureProviderWindow(provider);
	}

	/**
	 * Captures the window, including decorations.  This will use a {@link Robot} to create a 
	 * screen capture, which has the effect of getting all items within the window bounds.  This
	 * method is needed if you wish to capture child windows, like popups/hovers.
	 * 
	 * <P>Other capture methods will not use the screen capture mechanism, but rather will 
	 * directly render the given component.  In this case, subordinate windows will not be 
	 * captured.  For example, see {@link #captureProvider(Class)}.
	 * 
	 * @param provider the provider
	 */
	public void captureProviderWindow(ComponentProvider provider) {
		Window window = windowForComponent(provider.getComponent());
		captureWindow(window);
	}

	/**
	 * Captures the window, including decorations.  This will use a {@link Robot} to create a 
	 * screen capture, which has the effect of getting all items within the window bounds.  This
	 * method is needed if you wish to capture child windows, like popups/hovers.
	 * 
	 * <P>Other capture methods will not use the screen capture mechanism, but rather will 
	 * directly render the given component.  In this case, subordinate windows will not be 
	 * captured.  For example, see {@link #captureProvider(Class)}.
	 * 
	 * @param name the provider's name
	 * @param width the desired width
	 * @param height the desired height
	 */
	public void captureProviderWindow(String name, int width, int height) {
		waitForPostedSwingRunnables();

		ComponentProvider provider = tool.getWindowManager().getComponentProvider(name);
		assertNotNull("Unable to find provider in tool: " + name, provider);
		captureProviderWindow(provider, width, height);
	}

	/**
	 * Captures the window, including decorations.  This will use a {@link Robot} to create a 
	 * screen capture, which has the effect of getting all items within the window bounds.  This
	 * method is needed if you wish to capture child windows, like popups/hovers.
	 * 
	 * <P>Other capture methods will not use the screen capture mechanism, but rather will 
	 * directly render the given component.  In this case, subordinate windows will not be 
	 * captured.  For example, see {@link #captureProvider(Class)}.
	 * 
	 * @param provider the provider's name
	 * @param width the desired width
	 * @param height the desired height
	 */
	public void captureProviderWindow(ComponentProvider provider, int width, int height) {
		waitForPostedSwingRunnables();
		Window window = windowForComponent(provider.getComponent());
		captureWindow(window, width, height);
	}

	public <T extends ComponentProvider> T showProvider(Class<T> clazz) {
		ComponentProvider componentProvider = getProvider(clazz);
		if (componentProvider != null) {
			componentProvider.setVisible(true);
		}
		waitForPostedSwingRunnables();
		return clazz.cast(componentProvider);
	}

	public void closeProvider(Class<? extends ComponentProvider> clazz) {
		ComponentProvider componentProvider = getProvider(clazz);
		if (componentProvider != null) {
			componentProvider.setVisible(false);
		}
		waitForPostedSwingRunnables();
	}

	public void captureActionIcon(String actionName) {
		waitForSwing();
		DockingActionIf action = getAction(tool, actionName);
		ToolBarData tbData = action.getToolBarData();
		Icon icon = tbData.getIcon();
		captureIcon(icon);
	}

	public void captureIcon(Icon icon) {
		runSwing(() -> {
			ImageIcon imageIcon = ResourceManager.getImageIcon(icon);
			image = imageIcon.getImage();

			// The image returned here must be a BufferedImage, so create one
			// if not. It may be a ToolkitImage (eg: if the icon in question
			// is retrieved from Icons.java), which would fail on a cast to 
			// BufferedImage during the save operation.
			image = ImageUtils.getBufferedImage(image);
		});
	}

	public void captureDialog() {
		captureDialog(DialogComponentProvider.class);
	}

	public DialogComponentProvider getDialog() {
		return getDialog(DialogComponentProvider.class);
	}

	public DialogComponentProvider getDialog(Class<? extends DialogComponentProvider> clazz) {
		return waitForDialogComponent(clazz);

	}

	public void captureDialog(int width, int height) {
		captureDialog(DialogComponentProvider.class, width, height);
	}

	protected void paintFix(final Window window) {

// TODO
//		int sleepyTime = 10;
//		int totalTime = 0;
//		while (!window.isShowing() && totalTime < 2000) {
//			sleep(sleepyTime);
//			totalTime += sleepyTime;
//		}

		sleep(250);
	}

	public void captureDialog(String title) {
		DialogComponentProvider dialogProvider = waitForDialogComponent(title);
		JDialog dialog = (JDialog) getInstanceField("dialog", dialogProvider);
		waitForSwing();
		paintFix(dialog);
		runSwing(() -> generateImage(dialog));
	}

	public void captureDialog(Class<? extends DialogComponentProvider> clazz) {
		DialogComponentProvider dialogProvider = waitForDialogComponent(clazz);
		Assert.assertNotNull("Did not find a dialog to capture for class: " + clazz,
			dialogProvider);
		JDialog dialog = (JDialog) getInstanceField("dialog", dialogProvider);
		waitForSwing();
		paintFix(dialog);
		runSwing(() -> generateImage(dialog));
	}

	public void captureDialog(DialogComponentProvider provider) {

		Assert.assertNotNull("Dialog cannot be null", provider);

		JDialog dialog = (JDialog) getInstanceField("dialog", provider);

		paintFix(dialog);

		runSwing(() -> generateImage(dialog));
	}

	public void captureDialog(Class<? extends DialogComponentProvider> clazz, final int width,
			final int height) {
		DialogComponentProvider dialogProvider = waitForDialogComponent(clazz);
		final JDialog dialog = (JDialog) getInstanceField("dialog", dialogProvider);
		waitForPostedSwingRunnables();
		paintFix(dialog);
		if (width >= 0) {
			runSwing(() -> dialog.setSize(width, height));
		}

		waitForSwing();
		paintFix(dialog);

		runSwing(() -> generateImage(dialog));
	}

	public void captureWindow() {
		waitForPostedSwingRunnables();
		final JFrame toolFrame = tool.getToolFrame();
		paintFix(toolFrame);
		runSwing(() -> generateImage(toolFrame));
	}

	public void captureWindow(final Window window) {
		waitForPostedSwingRunnables();
		paintFix(window);
		runSwing(() -> generateImage(window));
	}

	public void captureWindow(final Window window, final int width, final int height) {
		waitForPostedSwingRunnables();

		runSwing(() -> window.setSize(width, height));

		waitForSwing();
		paintFix(window);
		runSwing(() -> generateImage(window));
	}

	public void captureToolWindow(final int width, final int height) {

		waitForPostedSwingRunnables();

		runSwing(() -> {
			JFrame toolFrame = tool.getToolFrame();
			toolFrame.setSize(width, height);
		});
		waitForSwing();
		paintFix(tool.getToolFrame());
		runSwing(() -> generateImage(tool.getToolFrame()));
	}

	public void captureDialog(final Dialog dialog) {
		waitForPostedSwingRunnables();
		paintFix(dialog);
		runSwing(() -> generateImage(dialog));
	}

	public void captureDialog(final Dialog dialog, final int width, final int height) {
		waitForPostedSwingRunnables();

		runSwing(() -> dialog.setSize(width, height));

		waitForSwing();
		paintFix(dialog);
		runSwing(() -> generateImage(dialog));
	}

	public void captureListingField(long address, String fieldName, int padding) {
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		plugin.goToField(addr(address), fieldName, 0, 0);

		FieldPanel fieldPanel = plugin.getFieldPanel();
		Rectangle cursorBounds = fieldPanel.getCursorBounds();
		ListingPanel listingPanel = plugin.getListingPanel();
		cursorBounds.setLocation(
			SwingUtilities.convertPoint(fieldPanel, cursorBounds.getLocation(), listingPanel));

		captureIsolatedComponent(listingPanel, 1300, 600);// feel free to make this bigger

		Field field = getField(cursorBounds.getLocation());
		int fieldWidth = field.getPreferredWidth();
		int fieldHeight = field.getHeight();

		int x = cursorBounds.x - padding;
		int y = cursorBounds.y - padding;
		crop(new Rectangle(x, y, fieldWidth + 2 * padding, fieldHeight + 2 * padding));
	}

	public void generateImage(Component c) {

		// Note: using the screen image has the downside of capturing non-Ghidra windows when 
		//       focus is lost.   Prefer the component painting itself.   This will not work
		//       for native constructs like window decorations.
		if (!(c instanceof Window)) {
			image = createRenderedImage(c);
			return;
		}

		try {
			image = createScreenImage(c);
		}
		catch (AWTException e) {
			error(e);
		}

	}

	public void captureComponents(List<Component> comps) {
		Rectangle rect = computeBounds(comps);
		BufferedImage combinedImage =
			new BufferedImage(rect.width, rect.height, BufferedImage.TYPE_INT_ARGB);
		Graphics g = combinedImage.getGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, rect.width, rect.height);

		for (Component component : comps) {
			int pad = 6;
			Point p = component.getLocationOnScreen();
			g.setColor(new Color(250, 250, 250));
			g.fillRoundRect(p.x - rect.x - pad, p.y - rect.y - pad, component.getWidth() + pad * 2,
				component.getHeight() + pad * 2, pad * 2, pad * 2);
		}
		for (Component component : comps) {
			int pad = 3;
			Point p = component.getLocationOnScreen();
			g.setColor(new Color(240, 240, 240));
			g.fillRoundRect(p.x - rect.x - pad, p.y - rect.y - pad, component.getWidth() + pad * 2,
				component.getHeight() + pad * 2, pad * 2, pad * 2);
		}

		for (Component component : comps) {
			image = captureComponent(component);
			Point p = component.getLocationOnScreen();
			g.drawImage(image, p.x - rect.x, p.y - rect.y, null);
		}
		ImageUtils.waitForImage(null, combinedImage);
		image = combinedImage;
	}

	public void captureMenuBarMenu(String menuName, String... subMenuNames) {
		showMenuBarMenu(menuName, subMenuNames);
		captureMenu();
	}

	public void captureMenuBarMenuHierachy(String menuName, String... subMenuNames) {
		List<Component> comps = showMenuBarMenu(menuName, subMenuNames);
		captureComponents(comps);
	}

	public void captureListingRange(long start, long end, int width) {
		waitForSwing();

		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		ListingPanel listingPanel = plugin.getListingPanel();

		plugin.goToField(addr(start), AddressFieldFactory.FIELD_NAME, 0, 0);
		fieldPanel.positionCursor(0);
		Rectangle startCursorBounds = fieldPanel.getCursorBounds();
		startCursorBounds.setLocation(
			SwingUtilities.convertPoint(fieldPanel, startCursorBounds.getLocation(), listingPanel));

		plugin.goToField(addr(end), AddressFieldFactory.FIELD_NAME, 0, 0, 0, false);
		Rectangle endCursorBounds = fieldPanel.getCursorBounds();
		endCursorBounds.setLocation(
			SwingUtilities.convertPoint(fieldPanel, endCursorBounds.getLocation(), listingPanel));

		int height = endCursorBounds.y + endCursorBounds.height;
		int extraHeight = height * 2;// arbitrary; big enough that we don't see scroll bars
		captureIsolatedComponent(plugin.getListingPanel(), width, extraHeight);
		int y = startCursorBounds.y;
		crop(new Rectangle(0, y, width - 40, height - y));
	}

	public void error(Exception e) {
		e.printStackTrace();
		System.exit(1);
	}

	public void setListingFieldWidth(final String fieldName, final int width) {
		runSwing(() -> {
			FormatManager newMinimizedFormatManager = getFormatManager();
			for (int i = 0; i < newMinimizedFormatManager.getNumModels(); i++) {
				FieldFormatModel formatModel = newMinimizedFormatManager.getModel(i);
				int numRows = formatModel.getNumRows();
				for (int row = 0; row < numRows; row++) {
					FieldFactory[] allRowFactories = formatModel.getFactorys(row);
					for (int col = allRowFactories.length - 1; col >= 0; col--) {
						FieldFactory fieldFactory = allRowFactories[col];

						if (fieldFactory.getFieldName().equals(fieldName)) {
							fieldFactory.setWidth(width);
							formatModel.updateRow(row);
							return;
						}
					}
				}
			}
		});
	}

	public Field getField(Point point) {
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		ListingPanel listingPanel = plugin.getListingPanel();
		FieldLocation loc = new FieldLocation();
		return listingPanel.getFieldPanel().getFieldAt(point.x, point.y, loc);
	}

	private FormatManager getFormatManager() {
		CodeBrowserPlugin cbp = getPlugin(tool, CodeBrowserPlugin.class);
		return cbp.getFormatManager();
	}

	public void leftClickCursor() {
		Rectangle cursor = getCursorBounds();
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		leftClick(fieldPanel, cursor.x, cursor.y);
		waitForPostedSwingRunnables();
	}

	public void rightClickCursor() {
		Rectangle cursor = getCursorBounds();
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		rightClick(fieldPanel, cursor.x, cursor.y);
		waitForPostedSwingRunnables();
	}

	public void middleClickCursor() {
		Rectangle cursor = getCursorBounds();
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		middleClick(fieldPanel, cursor.x, cursor.y);
		waitForPostedSwingRunnables();
	}

	public void doubleClickCursor() {
		Rectangle cursor = getCursorBounds();
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		doubleClick(fieldPanel, cursor.x, cursor.y);
		waitForPostedSwingRunnables();
	}

	private Rectangle computeBounds(List<Component> comps) {
		Point upperLeft = null;
		Point lowerRight = null;
		for (Component component : comps) {
			Point p1 = component.getLocationOnScreen();
			Dimension size = component.getSize();
			Point p2 = new Point(p1.x + size.width, p1.y + size.height);
			if (upperLeft == null) {
				upperLeft = p1;
				lowerRight = p2;
				continue;
			}
			upperLeft.x = Math.min(upperLeft.x, p1.x);
			upperLeft.y = Math.min(upperLeft.y, p1.y);
			lowerRight.x = Math.max(lowerRight.x, p2.x);
			lowerRight.y = Math.max(lowerRight.y, p2.y);
		}
		return new Rectangle(upperLeft.x, upperLeft.y, lowerRight.x - upperLeft.x,
			lowerRight.y - upperLeft.y);
	}

	private JMenuItem findMenu(JMenuBar menuBar, String name) {
		for (MenuElement subElement : menuBar.getSubElements()) {
			JMenuItem item = (JMenuItem) subElement;
			if (name.equals(item.getText())) {
				return item;
			}
		}
		Assert.fail("Could not find menu element: " + name);
		return null;
	}

	private JMenuItem findMenuElement(JMenu menu, String name) {
		int itemCount = menu.getItemCount();
		for (int i = 0; i < itemCount; i++) {
			JMenuItem item = menu.getItem(i);
			if (name.equals(item.getText())) {
				return item;
			}
		}
		Assert.fail("Could not find menu element: " + name);
		return null;
	}

	public void selectRow(final JTable table, final int rowIndex) {
		waitForTable(table);

		runSwing(() -> table.setRowSelectionInterval(rowIndex, rowIndex));
		waitForTable(table);
	}

	public void setSelected(final JToggleButton button, final boolean select) {

		runSwing(() -> button.setSelected(select));
	}

	private void waitForTable(JTable table) {
		if (!(table instanceof GTable)) {
			return;
		}

		GTable gTable = (GTable) table;
		TableModel model = gTable.getModel();
		if (!(model instanceof ThreadedTableModel<?, ?>)) {
			return;
		}

		ThreadedTableModel<?, ?> threadedModel = (ThreadedTableModel<?, ?>) model;
		waitForTableModel(threadedModel);
	}

	public void hideTableColumn(final GTable table, final String columnName) {
		runSwing(() -> {
			GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
			List<TableColumn> allColumns = columnModel.getAllColumns();
			for (TableColumn column : allColumns) {
				if (columnName.equals(column.getHeaderValue())) {
					columnModel.setVisible(column, false);
				}
			}
		});
	}

	public List<Component> showMenuBarMenu(final String menuName, final String... submenuNames) {
		waitForSwing();
		final List<Component> list = new ArrayList<>();
		runSwing(() -> {
			JMenuBar menuBar = tool.getToolFrame().getJMenuBar();
			list.add(menuBar);
			JMenuItem item = findMenu(menuBar, menuName);
			JMenu menu = (JMenu) item;
			JPopupMenu popupMenu = menu.getPopupMenu();
			Rectangle bounds = item.getBounds();
			popupMenu.show(menu.getParent(), bounds.x, bounds.y + bounds.height);
			list.add(popupMenu);
			for (String string : submenuNames) {
				menu = (JMenu) findMenuElement(menu, string);
				popupMenu = menu.getPopupMenu();
				bounds = menu.getBounds();
				popupMenu.show(menu, bounds.x + bounds.width, 0);
				list.add(popupMenu);
			}
		});
		waitForSwing();
//		sleep(5000);
		return list;
	}

	public void showColumnSettings(final GTable table, final String colName) {
		runSwing(() -> {
			ConfigurableColumnTableModel model = table.getConfigurableColumnTableModel();
			for (int i = 0; i < model.getColumnCount(); i++) {
				if (colName.equals(model.getColumnName(i))) {
					SettingsDefinition[] settings = model.getColumnSettingsDefinitions(i);
					SettingsDialog dialog = new SettingsDialog(null);
					dialog.show(table, model.getColumnName(i) + " Settings", settings,
						model.getColumnSettings(i));

				}
			}
		}, false);
		waitForSwing();
	}

	public void showTableColumn(final GTable table, final String columnName) {
		runSwing(() -> {
			GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
			List<TableColumn> allColumns = columnModel.getAllColumns();
			for (TableColumn column : allColumns) {
				if (columnName.equals(column.getHeaderValue())) {
					columnModel.setVisible(column, true);
				}
			}
		});
	}

	public void setSelectedAnayzer(Object analysisPanel, final String analyzerName) {
		final JTable table = (JTable) getInstanceField("table", analysisPanel);

		runSwing(() -> {
			int rowCount = table.getModel().getRowCount();
			for (int i = 0; i < rowCount; i++) {
				String name = table.getValueAt(i, 1).toString();
				if (name.equals(analyzerName)) {
					table.setRowSelectionInterval(i, i);
					break;
				}
			}
		});
	}

	public void showCommentDialog(String text) {
		performAction("Set EOL Comment", "CommentsPlugin", false);
		prepareCommentsDialog((CommentsDialog) getDialog(), text);
	}

	public void prepareCommentsDialog(final CommentsDialog dialog, final String annotationText) {
		runSwing(() -> {
			JTextArea textArea = (JTextArea) getInstanceField("eolField", dialog);
			textArea.setText(annotationText);
			JComboBox<?> combo = findComponent(dialog.getComponent(), JComboBox.class);
			int itemCount = combo.getItemCount();
			for (int i = 0; i < itemCount; i++) {
				Object itemAt = combo.getItemAt(i);
				if ("URL".equals(itemAt.toString())) {
					combo.setSelectedIndex(i);
					break;
				}
			}
		});

	}

	public void createBookmark(long address) {
		goToListing(address);
		performAction("Add Bookmark", "BookmarkPlugin", false);
		final CreateBookmarkDialog d = (CreateBookmarkDialog) getDialog();
		assertNotNull("Could not find the Create Bookmark dialog", d);
		runSwing(() -> {
			JTextField commentTextField = (JTextField) getInstanceField("commentTextField", d);
			commentTextField.setText("My Comment");
			@SuppressWarnings("unchecked")
			JComboBox<String> categoryComboBox =
				(JComboBox<String>) AbstractGenericTest.getInstanceField("categoryComboBox", d);
			categoryComboBox.setSelectedItem("fred");
		});

		pressOkOnDialog();
	}

	public void selectRow(final JTable table, final String searchString) {
		waitForTable(table);

		final int row = findRowByPartialText(table, searchString);
		runSwing(() -> {
			table.setRowSelectionInterval(row, row);

			Rectangle rect = table.getCellRect(row, 0, false);
			table.scrollRectToVisible(rect);
		});

		waitForTable(table);
	}

	public void scrollToRow(final JTable table, final int row) {
		runSwing(() -> {
			Rectangle rect = table.getCellRect(row, 0, false);
			table.scrollRectToVisible(rect);
		});
	}

	public int findRowByPartialText(final JTable table, final String searchString) {
		waitForTable(table);

		final AtomicReference<Integer> result = new AtomicReference<>();
		runSwing(() -> {
			TableModel model = table.getModel();
			int rowCount = model.getRowCount();
			int columnCount = model.getColumnCount();
			StringBuilder buffy = new StringBuilder();

			for (int row = 0; row < rowCount; row++) {
				buffy.delete(0, buffy.length());// clear and reuse

				for (int col = 0; col < columnCount; col++) {
					Object value = model.getValueAt(row, col);
					if (value == null) {
						continue;
					}

					String string = value.toString();
					buffy.append(string);
				}

				String rowString = buffy.toString();
				if (rowString.contains(searchString)) {
					result.set(row);
					return;
				}
			}
		});

		if (result.get() == null) {
			throw new AssertException("Unable to find row with text: " + searchString);
		}

		waitForTable(table);

		return result.get();
	}

	public void performMemorySearch(final String searchString) {
		performAction("Search Memory", "MemSearchPlugin", false);
		final DialogComponentProvider d = getDialog();
		assertNotNull("Could not find the Memory Search dialog", d);
		JTextField valueField = (JTextField) getInstanceField("valueField", d);
		setText(valueField, searchString);
		pressButtonByName(d.getComponent(), "Search All");
	}

	public void removeField(final String fieldName) {
		final CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		runSwing(() -> {
			FormatManager formatManager = plugin.getFormatManager();
			FieldFormatModel codeUnitFormat = formatManager.getCodeUnitFormat();
			codeUnitFormat.getNumRows();
			for (int row = 0; row < codeUnitFormat.getNumRows(); row++) {
				FieldFactory[] factorys = codeUnitFormat.getFactorys(row);
				for (int col = 0; col < factorys.length; col++) {
					if (fieldName.equals(factorys[col].getFieldName())) {
						codeUnitFormat.removeFactory(row, col);
						break;
					}
				}
			}
		});
	}

	public void showAnalysisOptions(String selectedAnalyzerName) {
		performAction("Auto Analyze", "AutoAnalysisPlugin", false);
		AnalysisOptionsDialog dialog = (AnalysisOptionsDialog) getDialog();
		Object panel = getInstanceField("panel", dialog);
		setSelectedAnayzer(panel, selectedAnalyzerName);
	}

	public void removeFlowArrows() {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			ListingPanel listingPanel = plugin.getListingPanel();
			@SuppressWarnings("unchecked")
			List<MarginProvider> list =
				(List<MarginProvider>) getInstanceField("marginProviders", listingPanel);
			for (MarginProvider marginProvider : list) {
				listingPanel.removeMarginProvider(marginProvider);
			}
		});
	}

	public void makeSelection(final AddressSet addrSet) {
		runSwing(
			() -> tool.firePluginEvent(
				new ProgramSelectionPluginEvent("test", new ProgramSelection(addrSet), program)),
			true);

	}

	public void addSelection(final long start, final long end) {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			AddressSet set = new AddressSet(plugin.getCurrentSelection());
			set.addRange(addr(start), addr(end));
			tool.firePluginEvent(
				new ProgramSelectionPluginEvent("test", new ProgramSelection(set), program));
		}, true);

	}

	public void makeSelection(long start, long end) {
		AddressSet addressSet = new AddressSet();
		addressSet.addRange(addr(start), addr(end));
		makeSelection(addressSet);
	}

	public void go(long address) {
		goToListing(address);
	}

	public void goToListing(long address) {
		goToListing(address, AddressFieldFactory.FIELD_NAME, true);
	}

	public void goToListing(long address, boolean scrollToMiddle) {
		goToListing(address, AddressFieldFactory.FIELD_NAME, scrollToMiddle);
	}

	public void goToListing(final long address, final String fieldName,
			final boolean scrollToMiddle) {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			plugin.goToField(addr(address), fieldName, 0, 0, 0, scrollToMiddle);
		});
		waitForPostedSwingRunnables();
	}

	public void positionCursor(long address) {
		positionCursor(address, AddressFieldFactory.FIELD_NAME);
	}

	public void positionCursor(final long address, final String fieldName) {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			plugin.goToField(addr(address), fieldName, 0, 0, 0, false);
		});
		waitForPostedSwingRunnables();

	}

	public void positionListingTop(final long address) {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			FieldPanel fieldPanel = plugin.getFieldPanel();
			plugin.goToField(addr(address), AddressFieldFactory.FIELD_NAME, 0, 0);
			fieldPanel.positionCursor(0);
		});
	}

	public void positionListingCenter(final long address) {
		runSwing(() -> {
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			plugin.goToField(addr(address), AddressFieldFactory.FIELD_NAME, 0, 0);
		});
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		plugin.goToField(addr(address), AddressFieldFactory.FIELD_NAME, 0, 0);
	}

	@Deprecated
	public void topOfListing(long address) {
		positionListingTop(address);
	}

	public Plugin loadPlugin(Class<? extends Plugin> clazz) {
		try {
			tool.addPlugin(clazz.getName());
			return env.getPlugin(clazz);
		}
		catch (PluginException e) {
			e.printStackTrace();
			System.exit(0);
		}
		return null;
	}

	public Plugin loadPlugin(String className) {
		try {
			Class<?> clazz = Class.forName(className);
			@SuppressWarnings("unchecked")
			Class<? extends Plugin> pluginClazz = (Class<? extends Plugin>) clazz;
			return loadPlugin(pluginClazz);
		}
		catch (ClassCastException e) {
			e.printStackTrace();
			System.exit(0);
		}
		catch (ClassNotFoundException e) {
			e.printStackTrace();
			System.exit(0);
		}
		return null;
	}

	public ComponentProvider getProvider(String name) {
		return tool.getWindowManager().getComponentProvider(name);
	}

	public <T extends ComponentProvider> T getProvider(Class<T> clazz) {
		return clazz.cast(tool.getWindowManager().getComponentProvider(clazz));
	}

	public DockableComponent getDockableComponent(Class<? extends ComponentProvider> clazz) {
		ComponentProvider provider = tool.getWindowManager().getComponentProvider(clazz);
		return getDockableComponent(provider);
	}

	public JButton findProviderToolBarButton(ComponentProvider provider, String actionName) {
		DockableComponent dockingComponent = getDockableComponent(provider);
		JButton button = (JButton) findComponentByName(dockingComponent, actionName);
		assertNotNull("Can't find button for action: " + actionName, button);
		return button;
	}

	/**
	 *
	 * @param value the address's long value
	 * @return the new address
	 * @deprecated use {@link #addr(long)} instead
	 */
	@Deprecated
	public Address address(long value) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
	}

//==================================================================================================
// Draw Methods
//==================================================================================================

	public Rectangle getBounds(final JComponent component) {
		final AtomicReference<Rectangle> ref = new AtomicReference<>();
		runSwing(() -> ref.set(component.getBounds()));
		return ref.get();
	}

	public void drawRectangleWithDropShadowAround(JComponent component, Color color, int padding) {
		Rectangle r = drawRectangleAround(component, Color.BLACK, padding);

		// move it back a bit to create the drop-shadow effect
		r.x -= padding;
		r.y -= padding;
		drawRectangle(color, r, 4);
	}

	public Rectangle drawRectangleAround(JComponent component, Color color, int padding) {
		return drawRectangleAround(component, null/*root*/, color, padding);
	}

	/**
	 * Draws a rectangle around the given component.  The root parameter is used to calculate
	 * screen coordinates.   This allows you to capture a sub-component of a UI, drawing
	 * rectangles around children of said sub-component.
	 * 
	 * <P>If you are unsure of what to pass for <code>root</code>, the call 
	 * {@link #drawRectangleAround(JComponent, Color, int)} instead.
	 * 
	 * @param component the component to be en-rectangled
	 * @param root the outermost container widget being displayed; null implies a 
	 * 		  top-level parent
	 * @param color the rectangle color
	 * @param padding the space between the rectangle and the component; more space makes
	 *        the component more visible 
	 * @return the bounds of the drawn rectangle
	 */
	public Rectangle drawRectangleAround(JComponent component, JComponent root, Color color,
			int padding) {
		Rectangle bounds = getBounds(component);
		Rectangle converted = SwingUtilities.convertRectangle(component.getParent(), bounds, root);
		drawRectangle(color, converted, padding, 4);
		return converted;
	}

	public Rectangle drawRectangle(Color c, Rectangle r, int padding, int thickness) {
		r.x -= padding;
		r.y -= padding;
		r.width += (2 * padding);
		r.height += (2 * padding);
		drawRectangle(c, r, thickness);
		return r;
	}

	public void drawBorder(Color c) {
		Graphics g = image.getGraphics();
		g.setColor(c);
		g.drawRect(0, 0, image.getWidth(null) - 1, image.getHeight(null) - 1);
	}

	public void drawRectangle(Color c, Rectangle rect, int thickness) {
		Graphics g = image.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		BasicStroke stroke = new BasicStroke(thickness);
		g2d.setStroke(stroke);

		g.setColor(c);
		g.drawRect(rect.x, rect.y, rect.width, rect.height);
	}

	public void fillRectangle(Color c, Rectangle rect) {
		Graphics g = image.getGraphics();
		g.setColor(c);
		g.fillRect(rect.x, rect.y, rect.width, rect.height);
	}

	public void drawOval(Color c, Rectangle rect, int thickness) {
		Graphics g = image.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		BasicStroke stroke = new BasicStroke(thickness);
		g2d.setStroke(stroke);

		g.setColor(c);
		g.drawOval(rect.x, rect.y, rect.width, rect.height);
	}

	public void drawText(String text, Color color, Point start, float size) {
		Graphics g = image.getGraphics();
		Graphics2D g2 = (Graphics2D) g;
		g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
			RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		Font font = g.getFont();
		g.setFont(font.deriveFont(size));
		g.setColor(color);
		g.drawString(text, start.x, start.y);
	}

	public void drawText(String text, Color color, Point start, Font font) {
		Graphics g = image.getGraphics();
		Graphics2D g2 = (Graphics2D) g;
		g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
			RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		g.setColor(color);
		g.setFont(font);
		g.drawString(text, start.x, start.y);
	}

	public void drawLine(Color c, int thickness, Point start, Point end) {
		Graphics g = image.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		BasicStroke stroke = new BasicStroke(thickness);
		g2d.setStroke(stroke);
		g.setColor(c);
		g.drawLine(start.x, start.y, end.x, end.y);
	}

	public void drawArrow(Color c, Point start, Point end) {
		drawArrow(c, 3, start, end, 12);
	}

	public void drawArrow(Color c, int thickness, Point start, Point end, int arrowSize) {
		Graphics g = image.getGraphics();
		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		BasicStroke stroke = new BasicStroke(thickness);
		g2d.setStroke(stroke);
		g.setColor(c);

		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		double unitX = 0;
		double unitY = 0;

		if (end.x == start.x) {
			unitY = 1;
		}
		else if (end.y == start.y) {
			unitX = 1;
		}
		else {
			double slope =
				((double) end.y - (double) start.y) / ((double) end.x - (double) start.x);
			double crossSlope = 1 / slope;
			unitX = Math.sqrt(1 / ((slope * slope) + 1));
			unitY = Math.sqrt(1 / ((crossSlope * crossSlope) + 1));
		}

		if (end.x < start.x) {
			unitX = -unitX;
		}
		if (end.y < start.y) {
			unitY = -unitY;
		}

		int crossx = end.x - (int) (unitX * arrowSize);
		int crossy = end.y - (int) (unitY * arrowSize);

		g.drawLine(start.x, start.y, crossx, crossy);

		int arrow1x = crossx - (int) (unitY * arrowSize);
		int arrow1y = crossy + (int) (unitX * arrowSize);
		int arrow2x = crossx + (int) (unitY * arrowSize);
		int arrow2y = crossy - (int) (unitX * arrowSize);

		Polygon p = new Polygon();
		p.addPoint(end.x, end.y);
		p.addPoint(arrow1x, arrow1y);
		p.addPoint(arrow2x, arrow2y);
		g.fillPolygon(p);
	}

//==================================================================================================
// End Draw Methods
//==================================================================================================

//==================================================================================================
// Image Methods
//==================================================================================================

	protected void writeFile(File imageFile) {

		try {
			writeImage(image, imageFile);
		}
		catch (Exception e) {
			error(e);
		}
	}

	protected BufferedImage readImage(File imageFile) {
		try {
			return ImageUtils.readFile(imageFile);
		}
		catch (IOException e) {
			error(e);
		}
		return null;
	}

	public Image crop(Rectangle bounds) {
		image = ImageUtils.crop(image, bounds);
		return image;
	}

	public Image padImage(Color c, int top, int left, int right, int bottom) {
		image = ImageUtils.padImage(image, c, top, left, right, bottom);
		return image;
	}

	public Image placeImagesSideBySide(Image left, Image right) {
		image = ImageUtils.placeImagesSideBySide(left, right);
		return image;
	}

	public BufferedImage createEmptyImage(int width, int height) {
		return ImageUtils.createEmptyImage(width, height);
	}

	/**
	 * Crops a part of the current image, keeping what is inside the given bounds.  This method
	 * creates a shape such that the top and bottom of the cropped image have a jagged line, 
	 * looking somewhat like a sideways lightening bolt.
	 * 
	 * @param bounds the bounds to keep
	 * @return the snippet
	 */
	public Image takeSnippet(Rectangle bounds) {
		int margin = 20;
		int topMargin = 4;
		padImage(Color.WHITE, 0, margin, 0, margin);
		int rise = 8;
		bounds.width += 2 * margin;

		GeneralPath topPath = new GeneralPath();
		GeneralPath bottomPath = new GeneralPath();
		GeneralPath path = new GeneralPath();
		int centerx = bounds.x + bounds.width / 2;

		topPath.moveTo(0, rise + topMargin);
		topPath.lineTo(centerx, topMargin);
		topPath.lineTo(centerx - rise, 2 * rise + topMargin);
		topPath.lineTo(bounds.width, rise + topMargin);

		bottomPath.moveTo(bounds.width, bounds.height + 3 * rise + topMargin);
		bottomPath.lineTo(centerx - rise, bounds.height + 4 * rise + topMargin);
		bottomPath.lineTo(centerx, bounds.height + 2 * rise + topMargin);
		bottomPath.lineTo(0, bounds.height + 3 * rise + topMargin);

		path.append(topPath, true);
		path.append(bottomPath, true);
		path.closePath();

		bounds.y -= 2 * rise + topMargin;
		bounds.height += 4 * rise + 2 * topMargin;
		crop(path, bounds);

		Graphics2D g2 = (Graphics2D) image.getGraphics();

		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		g2.setColor(Color.BLACK);
		g2.setStroke(new BasicStroke(3f));
		g2.draw(topPath);
		g2.draw(bottomPath);
		return image;
	}

	private void crop(Shape shape, Rectangle bounds) {
		BufferedImage newImage = createEmptyImage(bounds.width, bounds.height);
		Graphics2D g2 = (Graphics2D) newImage.getGraphics();
		g2.setClip(shape);
		g2.translate(-bounds.x, -bounds.y);
		g2.drawImage(image, 0, 0, null);
		image = newImage;

	}

//==================================================================================================
// End Image Methods
//==================================================================================================

	public void setDividerPercentage(final Class<? extends ComponentProvider> provider1,
			final Class<? extends ComponentProvider> provider2, final float percentage) {

		runSwing(() -> {
			Object splitNode = findSplitNode(provider1, provider2);
			SplitPanel splitPanel = (SplitPanel) getInstanceField("splitPane", splitNode);
			splitPanel.setDividerPosition(percentage);
		});
	}

	private Object findSplitNode(Class<? extends ComponentProvider> provider1,
			Class<? extends ComponentProvider> provider2) {
		DockingWindowManager windowMgr = DockingWindowManager.getActiveInstance();
		Object rootNode = getInstanceField("root", windowMgr);
		List<Object> nodePath1 = findNodePath(rootNode, provider1);
		List<Object> nodePath2 = findNodePath(rootNode, provider2);
		// the first node that differs should be the one we want;
		for (int i = 0; i < nodePath1.size(); i++) {
			Object n1 = nodePath1.get(i);
			Object n2 = nodePath2.get(i);
			if (n1 != n2) {
				return nodePath1.get(i - 1);
			}
		}
		return null;
	}

	private List<Object> findNodePath(Object rootNode,
			Class<? extends ComponentProvider> providerClass) {
		Object node = getInstanceField("child", rootNode);
		Object resultNode = findNode(node, providerClass);
		List<Object> list = new ArrayList<>();
		Object n = resultNode;
		while (n != null) {
			list.add(n);
			n = getInstanceField("parent", n);
		}
		Collections.reverse(list);
		return list;
	}

	private Object findNode(Object node, Class<? extends ComponentProvider> providerClass) {
		if ("SplitNode".equals(node.getClass().getSimpleName())) {
			Object child1 = getInstanceField("child1", node);
			Object resultNode = findNode(child1, providerClass);
			if (resultNode != null) {
				return resultNode;
			}
			Object child2 = getInstanceField("child2", node);
			return findNode(child2, providerClass);
		}
		// else must be comonentNode, see if it is the one we want
		Object placeHolder = getInstanceField("top", node);
		Object componentProvider = getInstanceField("componentProvider", placeHolder);
		if (componentProvider != null && componentProvider.getClass() == providerClass) {
			return node;
		}
		return null;
	}

	public <T extends JComponent> T findChildWithType(Container node, Class<T> cls,
			Predicate<T> pred) {
		synchronized (node.getTreeLock()) {
			if (cls.isInstance(node)) {
				T potential = cls.cast(node);
				if (pred == null || pred.test(potential)) {
					return potential;
				}
			}
			for (Component child : node.getComponents()) {
				if (!(child instanceof Container)) {
					return null;
				}
				Container cont = (Container) child;
				JComponent found = findChildWithType(cont, cls, pred);
				if (found != null) {
					return cls.cast(found);
				}
			}
		}
		return null;
	}

	public <T extends JComponent> T findComponent(final Class<T> cls, final Predicate<T> pred) {
		final DialogComponentProvider dialog = getDialog();
		final AtomicReference<T> result = new AtomicReference<>();
		runSwing(() -> {
			JComponent top = dialog.getComponent();
			result.set(findChildWithType(top, cls, pred));
		});
		waitForSwing();
		return result.get();
	}

	public Component showTab(final String title) {
		final DialogComponentProvider dialog = getDialog();
		final AtomicReference<Component> result = new AtomicReference<>();
		runSwing(() -> {
			JComponent top = dialog.getComponent();
			JTabbedPane tabs = findChildWithType(top, JTabbedPane.class, null);
			if (tabs == null) {
				throw new IllegalStateException("No tab pane is present in current dialog");
			}
			int index = tabs.indexOfTab(title);
			if (index == -1) {
				throw new IllegalStateException("No such tab by title: " + title);
			}
			tabs.setSelectedIndex(index);
			result.set(tabs.getSelectedComponent());
		});
		waitForSwing();
		return result.get();
	}
}
