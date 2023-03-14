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
package ghidra.framework.main;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.List;

import javax.swing.*;

import org.jdesktop.animation.timing.TimingTarget;
import org.jdesktop.animation.timing.TimingTargetAdapter;

import docking.DockingWindowManager;
import docking.dnd.*;
import docking.tool.ToolConstants;
import docking.util.image.ToolIconURL;
import docking.widgets.EmptyBorderButton;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.bean.GGlassPane;
import ghidra.util.exception.AssertException;
import help.Help;
import help.HelpService;
import util.CollectionUtils;
import utility.function.Dummy;

/**
 * Component that is a drop target for a DataTreeTransferable object.
 * If the object contains a domain file that is supported by a tool of
 * this tool template, then a tool is launched with the data in it.
 * <p>
 * This button can be used in one of two ways: to launch new instances of an associated tool
 * template, or to represent a running tool.
 */
class ToolButton extends EmptyBorderButton implements Draggable, Droppable {

	private DropTarget dropTarget;
	private DropTgtAdapter dropTargetAdapter;
	private DataFlavor[] acceptableFlavors; // data flavors that this component can support
	private DragSource dragSource;
	private DragGestureAdapter dragGestureAdapter;
	private DragSrcAdapter dragSourceAdapter;
	private int dragAction = DnDConstants.ACTION_MOVE;

	private FrontEndPlugin plugin;
	private ToolTemplate template;
	private PluginTool associatedRunningTool;

	private ToolServices toolServices;

	/**
	 * Construct a tool button that does not represent a running tool, using
	 * the default tool icon.
	 * @param plugin the plugin
	 * @param template the template
	 */
	ToolButton(FrontEndPlugin plugin, ToolTemplate template) {
		this(plugin, null, template, template.getIconURL());
		setHelpLocation("Run_Tool");
	}

	/**
	 * Construct a tool label that represents a running tool, using the
	 * default RUNNING_TOOL icon.
	 * @param plugin the plugin
	 * @param tool the running tool
	 * @param template the template
	 */
	ToolButton(FrontEndPlugin plugin, PluginTool tool, ToolTemplate template) {
		this(plugin, tool, template, tool.getIconURL());
		setHelpLocation("Run_Tool");
	}

	/**
	 * Construct a tool label that represents a running tool.
	 */
	private ToolButton(FrontEndPlugin plugin, PluginTool tool, ToolTemplate template,
			ToolIconURL iconURL) {
		super(iconURL.getIcon());
		this.plugin = plugin;
		associatedRunningTool = tool;
		this.template = template;
		setUpDragDrop();

		// configure the look and feel of the button
		setVerticalTextPosition(SwingConstants.BOTTOM);
		setHorizontalTextPosition(SwingConstants.CENTER);
		setMargin(new Insets(0, 0, 0, 0));

		addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (menuShowing()) {
					// assume we are on a Mac and do not wish to process the button pressed too
					return;
				}
				activateTool();
			}

			private boolean menuShowing() {
				MenuSelectionManager manager = MenuSelectionManager.defaultManager();
				MenuElement[] selectedPath = manager.getSelectedPath();
				return selectedPath != null && selectedPath.length != 0;
			}
		});

		toolServices = plugin.getTool().getToolServices();
		if (toolServices == null) {
			throw new AssertException("ToolButton requires ToolServices to run.");
		}

		if (!isRunningTool()) {
			setIcon(generateIcon());
		}
	}

	@Override
	public String getToolTipText() {
		if (associatedRunningTool != null) {
			return "<html>" +
				HTMLUtilities.escapeHTML(associatedRunningTool.getToolFrame().getTitle());
		}
		return "<html>" + HTMLUtilities.escapeHTML(template.getName());
	}

	public void launchTool(DomainFile domainFile) {
		openFilesAndOpenToolAsNecessary(List.of(domainFile), null);
	}

//==================================================================================================
// Droppable interface
//==================================================================================================

	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		// nothing to do
	}

	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		DataFlavor[] flavors = e.getCurrentDataFlavors();
		Transferable transferable = e.getTransferable();
		try {
			return checkForDrop(flavors, transferable);
		}
		catch (UnsupportedFlavorException e1) {
			// don't care; return false
		}
		catch (IOException e1) {
			// don't care; return false
		}
		return false;
	}

	@SuppressWarnings("unchecked") 	// our data; cast is OK
	private boolean checkForDrop(DataFlavor[] flavors, Transferable transferable)
			throws UnsupportedFlavorException, IOException {

		for (DataFlavor flavor : flavors) {
			if (flavor.equals(DataTreeDragNDropHandler.localDomainFileFlavor)) {
				Object draggedData =
					transferable.getTransferData(DataTreeDragNDropHandler.localDomainFileFlavor);
				return containsSupportedDataTypes((List<DomainFile>) draggedData);
			}
			else if (flavor.equals(ToolButtonTransferable.localToolButtonFlavor)) {
				Object draggedData =
					transferable.getTransferData(ToolButtonTransferable.localToolButtonFlavor);
				ToolButton draggedButton = (ToolButton) draggedData;
				if (draggedButton != null) {
					if (draggedButton.associatedRunningTool == associatedRunningTool) {
						// tool chest -> tool chest is not allowed (both runningTools are null).
						// runningTool -> same runningTool is not allowed.
						return false;
					}
					return true;
				}
			}
			else if (flavor.equals(VersionInfoTransferable.localVersionInfoFlavor)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The given list must contain only valid domain files (i.e., no folders or null items)
	 * @param fileList The list of file objects to validate
	 * @return true if <b>all</b> items in the list are supported
	 */
	private boolean containsSupportedDataTypes(List<DomainFile> fileList) {

		for (DomainFile file : fileList) {
			if (!isSupportedDataType(file)) {
				return false;
			}
		}

		// if we get here then no invalid items were found, so as long as there is data, it is valid
		return fileList.size() > 0;
	}

	@Override
	public void undoDragUnderFeedback() {
		// nothing to do
	}

	@Override
	public void add(Object obj, DropTargetDropEvent event, DataFlavor f) {

		if (f.equals(DataTreeDragNDropHandler.localDomainFileFlavor)) {
			resetButtonAfterDrag(this);

			@SuppressWarnings("unchecked")
			// we put the data in
			List<DomainFile> list = (List<DomainFile>) obj;
			openFilesAndOpenToolAsNecessary(list, null);
		}
		else if (f.equals(VersionInfoTransferable.localVersionInfoFlavor)) {
			VersionInfo info = (VersionInfo) obj;
			PluginTool tool = plugin.getTool();
			Project project = tool.getProject();
			ProjectData projectData = project.getProjectData();
			DomainFile file = projectData.getFile(info.getDomainFilePath());
			final DomainObject versionedObj = getVersionedObject(file, info.getVersionNumber());

			if (versionedObj != null) {
				DomainFile domainFile = versionedObj.getDomainFile();
				if (isSupportedDataType(domainFile)) {
					resetButtonAfterDrag(this);
					openFilesAndOpenToolAsNecessary(List.of(domainFile),
						() -> versionedObj.release(ToolButton.this));
				}
				else {
					versionedObj.release(ToolButton.this);
				}
			}
		}
		else {
			plugin.setToolButtonTransferable(null);
			ToolButton toolButton = (ToolButton) obj;
			resetButtonAfterDrag(toolButton);
			addFromToolButton(toolButton);
		}
	}

	private void addFromToolButton(ToolButton toolButton) {
		plugin.setToolButtonTransferable(null);
		PluginTool tool = null;
		if (associatedRunningTool != null && toolButton.associatedRunningTool != null) {
			final PluginTool t2 = toolButton.associatedRunningTool;
			Swing.runLater(() -> connectTools(associatedRunningTool, t2));
			return;
		}

		boolean accepted = false;
		if (toolButton.associatedRunningTool == null) {
			tool = plugin.getActiveWorkspace().runTool(toolButton.template);
			accepted = tool.acceptDomainFiles(associatedRunningTool.getDomainFiles());
			final PluginTool t = tool;
			Swing.runLater(() -> connectTools(t, associatedRunningTool));
		}
		else {
			tool = plugin.getActiveWorkspace().runTool(template);
			accepted = tool.acceptDomainFiles(toolButton.associatedRunningTool.getDomainFiles());
			final PluginTool t = tool;
			final PluginTool t2 = toolButton.associatedRunningTool;
			Swing.runLater(() -> connectTools(t, t2));
		}

		if (!accepted) {
			Msg.error(this, tool.getName() + " did not accept data.");
		}
	}

	/**
	 * Connect the tools in both directions.
	 */
	private void connectTools(PluginTool t1, PluginTool t2) {
		ToolManager tm = plugin.getActiveProject().getToolManager();
		ToolConnection tc = tm.getConnection(t1, t2);
		connectAll(tc);

		tc = tm.getConnection(t2, t1);
		connectAll(tc);
	}

	private void connectAll(ToolConnection tc) {
		String[] events = tc.getEvents();
		for (String element : events) {
			tc.connect(element);
		}
		plugin.updateToolConnectionDialog();
		Msg.info(this, "Connected all events for " + tc.getProducer().getName() + " to " +
			tc.getConsumer().getName());
	}

	private boolean isSupportedDataType(DomainFile file) {
		if (file == null) {
			return false;
		}

		Class<?> c = file.getDomainObjectClass();
		Class<?>[] classes =
			(associatedRunningTool != null) ? associatedRunningTool.getSupportedDataTypes()
					: template.getSupportedDataTypes();
		for (Class<?> element : classes) {
			if (element.isAssignableFrom(c)) {
				return true;
			}
		}
		return false;
	}

	private DomainObject getVersionedObject(DomainFile file, int versionNumber) {
		GetDomainObjectTask task = new GetDomainObjectTask(this, file, versionNumber);
		plugin.getTool().execute(task, 250);
		return task.getDomainObject();
	}

//==================================================================================================
// Draggable interface
//==================================================================================================

	/** Fix the button state after dragging/dropping, since this is broken in Java */
	private void resetButtonAfterDrag(JButton button) {
		// HACK: fix for error where the drag and drop system does not properly reset the state of
		// JButton.  If you drag away from and onto the same button and release, the button thinks
		// it is still pressed and armed (yeah, I know, dragging buttons is weird).
		ButtonModel buttonModel = button.getModel();
		buttonModel.setArmed(false);
		buttonModel.setPressed(false);
		buttonModel.setRollover(false);
		clearBorder();
	}

	/**
	 * Method called when the drag operation exits the drop target
	 * without dropping.
	 */
	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		plugin.setToolButtonTransferable(null);
		resetButtonAfterDrag(this);

		// Unusual Code Alert!
		// When dragging, we do not get mouseReleased() events, which we use to launch tools.
		// In this case, the drag was cancelled; if we are over ourselves, then simulate
		// the Java-eaten mouseReleased() call
		Container parent = getParent();
		if (parent == null) {
			return;
		}

		Point point = event.getLocation();
		if (point == null) {
			return;
		}
		SwingUtilities.convertPointFromScreen(point, parent);
		Component componentUnderMouse =
			SwingUtilities.getDeepestComponentAt(parent, point.x, point.y);

		if (componentUnderMouse == this) {
			handleMouseReleased();
		}

	}

	/**
	 * Return true if the object at the location in the DragGesture
	 * event is draggable.
	 *
	 * @param e event passed to a DragGestureListener via its
	 * dragGestureRecognized() method when a particular DragGestureRecognizer
	 * detects a platform dependent Drag and Drop action initiating
	 * gesture has occurred on the Component it is tracking.
	 * @see docking.dnd.DragGestureAdapter
	 */
	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		plugin.setToolButtonTransferable(new ToolButtonTransferable(this));
		return true;
	}

	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	@Override
	public Transferable getTransferable(Point p) {
		return plugin.getToolButtonTransferable();
	}

	@Override
	public void move() {
		resetButtonAfterDrag(this);
	}

	@Override
	public int getDragAction() {
		return dragAction;
	}

//==================================================================================================
// Package methods
//==================================================================================================

	void setToolTemplate(ToolTemplate template, Icon icon) {
		this.template = template;
		setIcon(icon);
	}

	ToolTemplate getToolTemplate() {
		return template;
	}

	boolean isRunningTool() {
		return associatedRunningTool != null;
	}

	void closeTool() {
		associatedRunningTool.close();
	}

	PluginTool getRunningTool() {
		return associatedRunningTool;
	}

	void dispose() {
		plugin = null;
		template = null;
		associatedRunningTool = null;
		dropTarget = null;
		dropTargetAdapter = null;
		acceptableFlavors = null;
		dragSource = null;
		dragGestureAdapter = null;
	}

//==================================================================================================
// Private methods(non-drag/drop)
//==================================================================================================

	private void activateTool() {
		if (associatedRunningTool == null) {
			// this is a button on the tool bar, so launch a new tool
			openFilesAndOpenToolAsNecessary(null, null);
		}
		else {
			associatedRunningTool.toFront();
		}
	}

	private void openFilesAndOpenToolAsNecessary(List<DomainFile> domainFiles,
			Runnable finishedCallback) {

		finishedCallback = Dummy.ifNull(finishedCallback);

		if (associatedRunningTool != null) {
			// this button has a running tool, no need to open one
			openDomainFiles(associatedRunningTool, domainFiles);
			return;
		}

		DockingWindowManager manager = DockingWindowManager.getInstance(this);
		final JFrame toolFrame = manager.getRootFrame();
		Component glassPane = toolFrame.getGlassPane();
		if (!(glassPane instanceof GGlassPane)) {
			// We cannot perform the tool launching animation, so just do the old fashion way
			Msg.debug(this, "Found root frame without a GGlassPane registered!");

			// try to recover without animation
			PluginTool newTool = plugin.getActiveWorkspace().runTool(template);
			openDomainFiles(newTool, domainFiles);
			finishedCallback.run();
			return;
		}

		launchToolWithAnimationAndOpenFiles(domainFiles, toolFrame, (GGlassPane) glassPane,
			finishedCallback);
	}

	private void launchToolWithAnimationAndOpenFiles(List<DomainFile> domainFiles, JFrame toolFrame,
			GGlassPane toolGlassPane, Runnable finishedCallback) {

		Icon icon = getIcon();
		Point buttonLocation = getLocation();
		Insets insets = getInsets();
		buttonLocation.x += insets.left;
		buttonLocation.y += insets.top;
		buttonLocation =
			SwingUtilities.convertPoint(getParent(), buttonLocation, toolFrame.getRootPane());

		// start the animation over top of this button, so it appears as though the tool is
		// launching from that button
		Rectangle startBounds =
			new Rectangle(buttonLocation, new Dimension(icon.getIconWidth(), icon.getIconHeight()));

		Dimension frameSize = toolFrame.getSize();

		// the final point over which the image will be painted
		Rectangle endBounds = new Rectangle(new Point(0, 0), frameSize);

		// Create our animation code: a zooming effect and an effect to move where the image is
		// painted.  These effects are independent code-wise, but work together in that the
		// mover will set the location and size, and the zoomer will will paint the image with
		// a transparency and a zoom level, which is affected by the movers bounds changing.
		Image image = ZoomedImagePainter.createIconImage(icon);
		final ZoomedImagePainter painter = new ZoomedImagePainter(startBounds, image);
		final ZoomImageRunner zoomRunner = new ZoomImageRunner(toolGlassPane, painter, icon);
		MoveImageRunner moveRunner =
			new MoveImageRunner(toolGlassPane, startBounds, endBounds, painter);

		TimingTarget finishedTarget = new TimingTargetAdapter() {
			@Override
			public void end() {
				toolGlassPane.removePainter(painter);
				try {
					// cleanup any residual painting effects
					toolGlassPane.paintImmediately(toolGlassPane.getBounds());
					openDomainFiles(domainFiles);
				}
				finally {
					// always restore the cursor
					GGlassPane.setAllGlassPanesBusy(false);
					finishedCallback.run();
				}
			}
		};
		zoomRunner.addTimingTargetListener(finishedTarget);

		// change to a busy cursor and block input
		GGlassPane.setAllGlassPanesBusy(true);

		moveRunner.run();
		zoomRunner.run();
	}

	private void openDomainFiles(List<DomainFile> domainFiles) {
		if (CollectionUtils.isBlank(domainFiles)) {
			plugin.getActiveWorkspace().runTool(template);
		}
		else {
			PluginTool tool = toolServices.launchTool(template.getName(), domainFiles);
			if (tool == null) {
				Msg.showError(this, getParent(), "Failed to Launch Tool",
					"Failed to launch " + template.getName() + " tool.\nSee log for details.");
			}
		}
	}

	private void openDomainFiles(PluginTool tool, List<DomainFile> domainFiles) {
		if (domainFiles == null) {
			return;
		}
		tool.acceptDomainFiles(domainFiles.toArray(DomainFile[]::new));
	}

	private void setUpDragDrop() {

		acceptableFlavors = new DataFlavor[] { DataTreeDragNDropHandler.localDomainFileFlavor,
			ToolButtonTransferable.localToolButtonFlavor,
			VersionInfoTransferable.localVersionInfoFlavor };

		// set up drop stuff
		dropTargetAdapter =
			new ToolButtonDropTgtAdapter(DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		dropTarget =
			new DropTarget(this, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		dropTarget.setActive(true);

		// set up drag stuff
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(this, dragAction, dragGestureAdapter);
	}

	private Icon generateIcon() {
		Icon icon = template.getIcon();
		if (isRunningTool()) {
			return icon;
		}

		return icon;
	}

	private void setHelpLocation(String anchorTag) {
		HelpService help = Help.getHelpService();
		help.registerHelp(this, new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, anchorTag));
	}

	private void handleMouseReleased() {
		activateTool();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ToolButtonDropTgtAdapter extends DropTgtAdapter {
		private boolean draggingOverValidDropTarget = false;

		public ToolButtonDropTgtAdapter(int acceptableDropActions,
				DataFlavor[] acceptableDropFlavors) {
			super(ToolButton.this, acceptableDropActions, acceptableDropFlavors);
		}

		@Override
		public void dragEnter(DropTargetDragEvent e) {
			super.dragEnter(e);
			if (super.isDropOk(e)) {
				ToolButton.this.setBorder(RAISED_BUTTON_BORDER);
				draggingOverValidDropTarget = true;
			}
		}

		@Override
		public void dragExit(DropTargetEvent e) {
			super.dragExit(e);
			if (draggingOverValidDropTarget) {
				clearBorder();
				draggingOverValidDropTarget = false;
			}
		}
	}
}
