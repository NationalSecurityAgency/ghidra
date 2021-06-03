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
package ghidra.util.bean;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import generic.util.WindowUtilities;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

/**
 * A component that acts as the general purpose glass pane for Java windows.  This component allows
 * Ghidra to easily change
 */
public class GGlassPane extends JComponent {
	private static final Cursor BUSY_CURSOR = Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR);
	private static final Cursor DEFAULT_CURSOR = Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR);

	private static WeakSet<GGlassPane> systemGlassPanes =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	/** A listener to block input and beep when a click is executed */
	private MouseListener blockingMouseListener = new MouseAdapter() {
		@Override
		public void mouseClicked(MouseEvent e) {
			Toolkit.getDefaultToolkit().beep();
		}
	};

	private List<GGlassPanePainter> painters = new ArrayList<>();

	private Cursor nonBusyCursor = DEFAULT_CURSOR;
	private boolean isBusy;

	/**
	 * Default constructor.
	 * <p>
	 * <b>NOTE: </b>You must call {@link #setVisible(boolean) setVisible(true)} on this component <b>after adding it
	 * to the component</b>.  This is because the component will set the visibility to that of
	 * the previous glass pane, which is false by default.
	 */
	public GGlassPane() {
		systemGlassPanes.add(this);
	}

	/**
	 * Adds a painter that will be called when this pane's {@link #paintComponent(Graphics)} 
	 * method is called.
	 * @param painter the painter to add
	 */
	public void addPainter(GGlassPanePainter painter) {
		painters.add(painter);
		repaint();
	}

	public void removePainter(GGlassPanePainter painter) {
		painters.remove(painter);
		repaint();
	}

	/**
	 * When set busy is called, a busy cursor will be displayed <b>and</b> all user mouse and 
	 * keyboard events will be blocked.
	 * 
	 * @param isBusy True to block events and show the busy cursor; false to restore events and
	 *               to restore the default cursor.
	 */
	public void setBusy(boolean isBusy) {
		this.isBusy = isBusy;
		showBusyCursor(isBusy);

		// always remove before adding, as this prevents multiple additions
		removeMouseListener(blockingMouseListener);
		if (isBusy) {
			addMouseListener(blockingMouseListener);
		}
		paintImmediately(getBounds());
	}

	/**
	 * Sets the busy state of all glass panes created in the VM.
	 */
	public static void setAllGlassPanesBusy(boolean isBusy) {
		for (GGlassPane glassPane : systemGlassPanes) {
			glassPane.setBusy(isBusy);
		}
	}

	/**
	 * Returns true if this glass pane is blocking user input.
	 */
	public boolean isBusy() {
		return isBusy;
	}

	public void showBusyCursor(boolean showBusyCursor) {
		Cursor currentCursor = getCursor();
		if (showBusyCursor) {
			if (currentCursor.equals(BUSY_CURSOR)) {
				return; // already showing busy
			}

			nonBusyCursor = currentCursor;
			setCursor(BUSY_CURSOR);
		}
		else {
			if (!currentCursor.equals(BUSY_CURSOR)) {
				return; // already showing busy
			}

			setCursor(nonBusyCursor);
		}
	}

	@Override
	protected void paintComponent(Graphics g) {
		for (GGlassPanePainter painter : painters) {
			painter.paint(this, g);
		}

//        WindowUtilities.bringModalestDialogToFront();

// easy debug indicator        
//        Rectangle bounds = getBounds();
//        Graphics2D g2 = (Graphics2D) g;
//        g2.setComposite( AlphaComposite.getInstance( AlphaComposite.SrcOver.getRule(), 0.5f ) );
//        g2.setColor( Color.BLUE );
//        g2.fill( bounds );
	}

	@Override
	public boolean contains(int x, int y) {
		Cursor currentCursor = getCursor();
		if (currentCursor.equals(BUSY_CURSOR)) {
			return true; // the busy cursor shows over *everything*
		}
		return false;
	}

	public static GGlassPane getGlassPane(Component component) {

		Window window = WindowUtilities.windowForComponent(component);
		if (window instanceof JFrame) {
			JFrame frame = (JFrame) window;
			Component glass = frame.getGlassPane();

			if (!(glass instanceof GGlassPane)) {
				Msg.error(GGlassPane.class, "GGlassPane not installed on window: " + window,
					new AssertException());
				return null;
			}

			return ((GGlassPane) glass);
		}
		else if (window instanceof JDialog) {
			JDialog frame = (JDialog) window;
			Component glass = frame.getGlassPane();

			if (!(glass instanceof GGlassPane)) {
				Msg.error(GGlassPane.class, "GGlassPane not installed on window: " + window,
					new AssertException());
				return null;
			}

			return ((GGlassPane) glass);
		}
		return null;
	}
}
