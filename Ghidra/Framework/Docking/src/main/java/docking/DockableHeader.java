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
package docking;

import java.awt.*;
import java.awt.dnd.*;
import java.awt.event.InputEvent;
import java.awt.event.MouseListener;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.Animator.RepeatBehavior;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import docking.help.Help;
import docking.help.HelpService;
import docking.util.AnimationUtils;
import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import resources.ResourceManager;

/**
 * Component for providing component titles and toolbar. Also provides Drag
 * source functionality.
 */
public class DockableHeader extends GenericHeader
		implements DragGestureListener, DragSourceListener {

	private DockableComponent dockComp;

	private DragCursorManager dragCursorManager = createDragCursorManager();
	private DragSource dragSource = null;
	private boolean isDocking;

	private Animator focusAnimator;

	/**
	 * Constructs a new DockableHeader for the given dockableComponent.
	 * 
	 * @param dockableComp the dockableComponent that this header is for.
	 * @param isDocking true means this widget can be dragged and docked by the user
	 */
	DockableHeader(DockableComponent dockableComp, boolean isDocking) {
		this.dockComp = dockableComp;
		this.isDocking = isDocking;

		setComponent(dockableComp);

		dragSource = new DragSource();

		ComponentPlaceholder info = dockableComp.getComponentWindowingPlaceholder();

		setTitle(info.getFullTitle());
		setIcon(info.getIcon());

		toolBarMgr.dispose(); // reset the default manager before we create our own
		toolBarMgr = new DockableToolBarManager(dockableComp, this);

		dragSource.createDefaultDragGestureRecognizer(titlePanel.getDragComponent(),
			DnDConstants.ACTION_MOVE, DockableHeader.this);

		resetComponents();
	}

	@Override
	// overridden to use our DockableComponent
	public void requestFocus() {
		validateFocusability();
		dockComp.requestFocus();
	}

	@Override
	public void setSelected(boolean hasFocus) {
		if (!hasFocus) {
			if (focusAnimator != null) {
				focusAnimator.stop();
				focusAnimator = null;
			}
		}

		super.setSelected(hasFocus);
	}

	void installRenameAction(MouseListener listener) {
		titlePanel.installRenameAction(listener);
	}

	void setHelp(HelpLocation location) {
		HelpService service = Help.getHelpService();
		if (location == null) {
			service.clearHelp(titlePanel);
		}
		else {
			service.registerHelp(titlePanel, location);
		}
	}

	/**
	 * Signals to use the GUI to make this header (and its provider) stand out from the rest.
	 */
	void emphasize() {
		DockingWindowManager manager = DockingWindowManager.getInstance(this);
		if (manager == null) {
			return;
		}

		JFrame toolFrame = manager.getRootFrame();
		Component glassPane = toolFrame.getGlassPane();
		if (!(glassPane instanceof GGlassPane)) {
			return;
		}

		if (focusAnimator != null && focusAnimator.isRunning()) {
			// prevent multiple animation
			return;
		}

		focusAnimator = createEmphasizingAnimator(toolFrame);
	}

	protected Animator createEmphasizingAnimator(JFrame parentFrame) {

		double random = Math.random();
		int choices = 7;
		int value = (int) (choices * random);

		switch (value) {
			case 0:
				return AnimationUtils.shakeComponent(component);
			case 1:
				return AnimationUtils.rotateComponent(component);
			case 2:
				return AnimationUtils.pulseComponent(component);
			case 3:
				return AnimationUtils.showTheDragonOverComponent(component);
			case 4:
				return AnimationUtils.focusComponent(component);
			case 5:
				return emphasizeDockableComponent();
			default:
				return raiseComponent(parentFrame);
		}
	}

	private Animator emphasizeDockableComponent() {

		if (!AnimationUtils.isAnimationEnabled()) {
			return null;
		}

		ComponentPlaceholder placeholder = dockComp.getComponentWindowingPlaceholder();
		ComponentNode node = placeholder.getNode();
		WindowNode windowNode = node.getTopLevelNode();
		Set<ComponentNode> componentNodes = new HashSet<>();
		getComponents(windowNode, componentNodes);

		//@formatter:off
		Set<Component> components = componentNodes.stream()
			  .map(cn -> cn.getComponent())
			  .filter(c -> c != null)
			  .filter(c -> !SwingUtilities.isDescendingFrom(component, c))
			  .collect(Collectors.toSet())
			  ;
		//@formatter:on

		components.remove(component);

		EmphasizeDockableComponentAnimationDriver driver =
			new EmphasizeDockableComponentAnimationDriver(component, components);
		return driver.animator;
	}

	private void getComponents(Node node, Set<ComponentNode> results) {

		List<Node> children = node.getChildren();
		for (Node child : children) {
			if (child instanceof ComponentNode) {
				results.add((ComponentNode) child);
			}
			else {
				getComponents(child, results);
			}
		}
	}

	private Animator raiseComponent(JFrame parent) {
		if (isOnlyComponentInParent(parent)) {
			return super.createEmphasizingAnimator();
		}
		return AnimationUtils.focusComponent(component);
	}

	private boolean isOnlyComponentInParent(JFrame parentFrame) {
		return !isInSplitPanel(); // no split parent means a single component in the window
	}

	private boolean isInSplitPanel() {
		Container parent = component.getParent();
		while (parent != null && !(parent instanceof SplitPanel)) {
			parent = parent.getParent();
		}

		return (parent instanceof SplitPanel);
	}

	private void validateFocusability() {
		Container focusCycleRootAncestor = dockComp.getFocusCycleRootAncestor();
		FocusTraversalPolicy policy = focusCycleRootAncestor.getFocusTraversalPolicy();
		Component firstComponent = policy.getFirstComponent(dockComp);
		if (firstComponent == null) {
			ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
			Msg.debug(this,
				"Found a ComponentProvider that does not contain a " + "focusable component: " +
					info.getTitle() + ".  ComponentProviders are " +
					"required to have at least one focusable component!");
			setSelected(false); // can't select it can't take focus
		}
	}

	@Override
	public void dragGestureRecognized(DragGestureEvent event) {
		if (!isDocking) {
			return;
		}

		// if any button other than MB1 is pressed, don't attempt to process the drag and drop event
		InputEvent ie = event.getTriggerEvent();
		int modifiers = ie.getModifiersEx();
		if ((modifiers & InputEvent.BUTTON2_DOWN_MASK) != 0 ||
			(modifiers & InputEvent.BUTTON3_DOWN_MASK) != 0) {
			return;
		}
		DockableComponent.DROP_CODE = DropCode.WINDOW;
		DockableComponent.DROP_CODE_SET = true;
		DockableComponent.SOURCE_INFO = dockComp.getComponentWindowingPlaceholder();

		dragCursorManager.dragStarted();

		dragSource.startDrag(event, DragSource.DefaultMoveNoDrop,
			new ComponentTransferable(new ComponentTransferableData(dockComp)), this);
	}

	@Override
	public void dragDropEnd(DragSourceDropEvent event) {
		dragCursorManager.restoreCursorOnPreviousDraggedOverComponent();
		dragCursorManager.dragEnded();

		ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
		DockingWindowManager winMgr = info.getNode().winMgr;
		if (DockableComponent.DROP_CODE == DropCode.INVALID) {
			return;
		}

// TODO	- Mac doesn't get the drop success correct when undocking a component (dragging out of
//		  the Java app
//		else if ( !event.getDropSuccess() ) {
//		    return;
//		}
//		else
		if (DockableComponent.DROP_CODE == DropCode.WINDOW) {
			winMgr.movePlaceholder(info, event.getLocation());
		}
		else {
			winMgr.movePlaceholder(info, DockableComponent.TARGET_INFO,
				DockableComponent.DROP_CODE.getWindowPosition());
		}
	}

	@Override
	public void dragEnter(DragSourceDragEvent event) {
		setCursor(event);
	}

	@Override
	public void dragExit(DragSourceEvent event) {
		setCursor(event);
	}

	@Override
	public void dragOver(DragSourceDragEvent event) {
		setCursor(event);
	}

	/**
	 * Sets the drag/drop cursor based on the current drop code.
	 * 
	 * @param event the event containing the drag source context on which to set the cursor.
	 */
	private void setCursor(DragSourceEvent event) {
		// TODO not sure why we needed this mechanic.  It is wrong on the Mac.  What is the use case?		
//		if (!DockableComponent.DROP_CODE_SET) {
//			return;
//		}

		DockableComponent.DROP_CODE_SET = false;
		Cursor c = DockableComponent.DROP_CODE.getCursor();
		dragCursorManager.setCursor(event, c);
	}

	@Override
	public void dropActionChanged(DragSourceDragEvent event) {
		// don't care
	}

	private DragCursorManager createDragCursorManager() {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			return new MacDragCursorManager();
		}
		return new DragCursorManager();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DragCursorManager {

		void setCursor(DragSourceEvent event, Cursor dragCursor) {
			DragSourceContext context = event.getDragSourceContext();
			context.setCursor(dragCursor); // use Java's normal mechanism
		}

		void dragStarted() {
			// no-op; dummy implementation
		}

		void dragEnded() {
			// no-op; dummy implementation
		}

		void restoreCursorOnPreviousDraggedOverComponent() {
			// no-op; dummy implementation
		}
	}

	private class MacDragCursorManager extends DragCursorManager {

		private Map<Component, Cursor> defaultCursors = new HashMap<>();
		private Component componentUnderDrag;

		@Override
		void setCursor(DragSourceEvent event, Cursor dragCursor) {
			ComponentPlaceholder placeholder = DockableComponent.DRAGGED_OVER_INFO;

			Component mousedComponent = null;
			if (placeholder == null) {
				// Must not be over any component; This can happen when over a split pane 
				// resize area or outside of the window
				super.setCursor(event, dragCursor);
				return;
			}

			int x = event.getX();
			int y = event.getY();
			Point screenPoint = new Point(x, y);

			DockableComponent draggedOverComponent = placeholder.getComponent();
			SwingUtilities.convertPointFromScreen(screenPoint, draggedOverComponent);
			Component hoveredComponent = SwingUtilities.getDeepestComponentAt(draggedOverComponent,
				screenPoint.x, screenPoint.y);

			mousedComponent = hoveredComponent;
			if (mousedComponent == null) {
				mousedComponent = placeholder.getComponent();
			}

			if (componentUnderDrag != mousedComponent) {
				restoreCursorOnPreviousDraggedOverComponent();
			}

			componentUnderDrag = mousedComponent;
			mousedComponent.setCursor(dragCursor);

			// also do the preferred thing, in case they ever fix this on the Mac
			super.setCursor(event, dragCursor);
		}

		@Override
		void restoreCursorOnPreviousDraggedOverComponent() {
			if (componentUnderDrag == null) {
				return;
			}

			Cursor restoreCursor = defaultCursors.get(componentUnderDrag);
			Window window = WindowUtilities.windowForComponent(componentUnderDrag);
			if (window != null) { // We've seen this happen when docking/undocking windows
				Cursor windowCursor = defaultCursors.get(window);
				window.setCursor(windowCursor);
			}

			componentUnderDrag.setCursor(restoreCursor);
			componentUnderDrag = null;
		}

		@Override
		void dragStarted() {

			defaultCursors.clear();

			Window[] windows = Window.getWindows();
			for (Window window : windows) {
				storeCursors(window);
			}
		}

		private void storeCursors(Container c) {
			defaultCursors.put(c, c.getCursor());
			Component[] children = c.getComponents();
			for (Component child : children) {
				if (child instanceof Container) {
					storeCursors((Container) child);
				}
			}
		}

		@Override
		void dragEnded() {
			defaultCursors.clear();
		}
	}

	public static class EmphasizeDockableComponentAnimationDriver {

		private Animator animator;
		private GGlassPane glassPane;
		private EmphasizeDockableComponentPainter rotatePainter;

		EmphasizeDockableComponentAnimationDriver(Component component, Set<Component> others) {

			glassPane = AnimationUtils.getGlassPane(component);
			rotatePainter = new EmphasizeDockableComponentPainter(component, others);

			double start = 0;
			double max = 1;
			int duration = 1000;
			animator = PropertySetter.createAnimator(duration, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);

			animator.setRepeatCount(2);
			animator.setRepeatBehavior(RepeatBehavior.REVERSE);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(rotatePainter);

			animator.start();
		}

		public void setPercentComplete(double percentComplete) {
			rotatePainter.setPercentComplete(percentComplete);
			glassPane.repaint();
		}

		void done() {
			glassPane.repaint();
			glassPane.removePainter(rotatePainter);
		}
	}

	private static class EmphasizeDockableComponentPainter implements GGlassPanePainter {

		private Set<ComponentPaintInfo> otherComponentInfos = new HashSet<>();
		private Image image;

		private Component component;
		private Rectangle cBounds;
		private double percentComplete = 0.0;

		EmphasizeDockableComponentPainter(Component component, Set<Component> otherComponents) {
			this.component = component;
			this.image = ImageUtils.createImage(component);

			for (Component otherComponent : otherComponents) {
				ComponentPaintInfo info = new ComponentPaintInfo(otherComponent);
				otherComponentInfos.add(info);
			}
		}

		private class ComponentPaintInfo {

			private Component myComponent;
			private Image myImage;

			ComponentPaintInfo(Component component) {
				this.myComponent = component;
				this.myImage = ImageUtils.createImage(component);
			}

			Image getImage() {
				return myImage;
			}

			Rectangle getRelativeBounds(Component other) {
				Rectangle r = myComponent.getBounds();
				return SwingUtilities.convertRectangle(myComponent.getParent(), r, other);
			}
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Graphics2D g2d = (Graphics2D) g;
			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			Color background = new Color(218, 232, 250);
			g.setColor(background);

			Rectangle othersBounds = null;
			for (ComponentPaintInfo info : otherComponentInfos) {

				Rectangle b = info.getRelativeBounds(glassPane);
				if (othersBounds == null) {
					othersBounds = b;
				}
				else {
					othersBounds.add(b);
				}
			}

			if (othersBounds == null) {
				// No other components in this window.  In this case, use the bounds of the 
				// active component.  This has the effect of showing the image behind the 
				// active component.
				Rectangle componentBounds = component.getBounds();
				componentBounds = SwingUtilities.convertRectangle(component.getParent(),
					componentBounds, glassPane);
				othersBounds = componentBounds;

				othersBounds = new Rectangle();
			}

			g2d.fillRect(othersBounds.x, othersBounds.y, othersBounds.width, othersBounds.height);

			ImageIcon ghidra = ResourceManager.loadImage("images/GhidraIcon256.png");
			Image ghidraImage = ghidra.getImage();

			double scale = percentComplete * 7;
			int gw = ghidraImage.getWidth(null);
			int gh = ghidraImage.getHeight(null);
			int w = (int) (gw * scale);
			int h = (int) (gh * scale);

			Rectangle gpBounds = glassPane.getBounds();
			double cx = gpBounds.getCenterX();
			double cy = gpBounds.getCenterY();
			int offsetX = (int) (cx - (w >> 1));
			int offsetY = (int) (cy - (h >> 1));

			Shape originalClip = g2d.getClip();
			if (!othersBounds.isEmpty()) {
				// restrict the icon to the 'others' area; otherwise, place it behind the provider
				g2d.setClip(othersBounds);
			}
			g2d.drawImage(ghidraImage, offsetX, offsetY, w, h, null);
			g2d.setClip(originalClip);

			paintOthers(glassPane, (Graphics2D) g, background);

			Rectangle b = component.getBounds();
			Point p = new Point(b.getLocation());
			p = SwingUtilities.convertPoint(component.getParent(), p, glassPane);

			g2d.setRenderingHints(new RenderingHints(null));
			g2d.drawImage(image, p.x, p.y, b.width, b.height, null);
		}

		private void paintOthers(GGlassPane glassPane, Graphics2D g2d, Color background) {

			if (cBounds == null) {
				cBounds = component.getBounds();
				cBounds =
					SwingUtilities.convertRectangle(component.getParent(), cBounds, glassPane);
			}

			double destinationX = cBounds.getCenterX();
			double destinationY = cBounds.getCenterY();

			g2d.setColor(background);
			for (ComponentPaintInfo info : otherComponentInfos) {

				Rectangle b = info.getRelativeBounds(glassPane);
				double scale = 1 - percentComplete;
				int w = (int) (b.width * scale);
				int h = (int) (b.height * scale);

				int offsetX = b.x - ((w - b.width) >> 1);
				int offsetY = b.y - ((h - b.height) >> 1);

				double deltaX = destinationX - offsetX;
				double deltaY = destinationY - offsetY;

				double moveX = percentComplete * deltaX;
				double moveY = percentComplete * deltaY;
				offsetX += moveX;
				offsetY += moveY;

				g2d.drawImage(info.getImage(), offsetX, offsetY, w, h, null);
			}
		}
	}

}
