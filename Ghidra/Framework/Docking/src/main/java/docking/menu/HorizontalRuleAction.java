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
package docking.menu;

import java.awt.Dimension;
import java.awt.Graphics;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GDHtmlLabel;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.util.HTMLUtilities;

/**
 * An action that can be added to a menu in order to separate menu items into groups
 */
public class HorizontalRuleAction extends DockingAction {
	private static final String PADDING = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

	private static int idCount = 0;

	/**
	 * Constructor
	 * 
	 * @param owner the action owner
	 * @param topName the name that will appear above the separator bar
	 * @param bottomName the name that will appear below the separator bar
	 */
	public HorizontalRuleAction(String owner, String topName, String bottomName) {
		super("HorizontalRuleAction: " + ++idCount, owner, false);
		setEnabled(false);

		markHelpUnnecessary();

		MenuData menuData = new MenuData(new String[] { "" });
		// The menu name is both names, one over the other, in a small, light grayish font.
		String topHtml = HTMLUtilities.escapeHTML(topName);
		String bottomHtml = HTMLUtilities.escapeHTML(bottomName);
		menuData.setMenuItemNamePlain(String.format("""
				<html><CENTER><FONT SIZE=2 COLOR="%s">%s<BR>%s</FONT></CENTER>
				""", Palette.SILVER, topHtml, bottomHtml));
		setMenuBarData(menuData);

		// the description is meant to be used for the tooltip and is larger
		setDescription(String.format("""
				<html><CENTER><B>%s</B><HR><B>%s</B></CENTER>
				""", PADDING + topHtml + PADDING, PADDING + bottomHtml + PADDING));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// this does't actually do anything
	}

	@Override
	public JSeparator createMenuComponent(boolean isPopup) {
		String[] menuPath = getMenuBarData().getMenuPath();
		String name = menuPath[menuPath.length - 1];
		String description = getDescription();
		return new LabeledSeparator(name, description);
	}

	private static class LabeledSeparator extends JSeparator {

		private final int EMTPY_SEPARATOR_HEIGHT = 10;
		private final int TEXT_SEPARATOR_HEIGHT = 32;
		private JLabel renderer = new GDHtmlLabel();

		private int separatorHeight = EMTPY_SEPARATOR_HEIGHT;

		private LabeledSeparator(String name, String description) {
			setBorder(BorderFactory.createEmptyBorder(20, 0, 20, 0));
			renderer.setText(name);
			DockingUtils.setTransparent(renderer);
			renderer.setHorizontalAlignment(SwingConstants.CENTER);
			renderer.setVisible(true);

			if (!StringUtils.isBlank(name)) {
				separatorHeight = TEXT_SEPARATOR_HEIGHT;
			}

// IF WE CHOOSE TO SHOW TOOLTIPS (and below too)...
//            setToolTipText( description );
		}

		@Override
		protected void paintComponent(Graphics g) {
			Dimension d = getSize();

			// some edge padding, for classiness
			int pad = 10;
			int center = separatorHeight >> 1;
			int x = 0 + pad;
			int y = center;
			int w = d.width - pad;
			g.setColor(getForeground());
			g.drawLine(x, y, w, y);

			// drop-shadow
			g.setColor(getBackground());
			g.drawLine(x, (y + 1), w, (y + 1));

			// now add our custom text
			renderer.setSize(getSize());
			renderer.paint(g);
		}

		@Override
		public Dimension getPreferredSize() {
			// assume horizontal
			return new Dimension(0, separatorHeight);
		}

		@Override
		public Dimension getMinimumSize() {
			return new Dimension(0, separatorHeight);
		}

//
// USE THE CODE BELOW IF WE WANT TOOLTIPS
//
//          @Override
//        public String getToolTipText( MouseEvent event ) {
//            // We only want to show the tooltip when the user is over the label.  Since the label
//            // is not on the screen, we cannot ask it if the mouse location is within its bounds.
//            Dimension labelSize = renderer.getPreferredSize();
//            if ( labelSize.height == 0 && labelSize.width == 0 ) {
//                return null;
//            }
//
//            Dimension mySize = getSize();
//            int centerX = mySize.width >> 1;
//
//            int labelMidPoint = labelSize.width >> 1;
//            int labelStartX = centerX - labelMidPoint;
//            int labelEndX = centerX + labelMidPoint;
//
//            Point mousePoint = event.getPoint();
//            boolean insideLabel = (mousePoint.x >= labelStartX) && (mousePoint.x <= labelEndX);
//            if ( !insideLabel ) {
//                return null;
//            }
//            return getToolTipText();
//        }
//
//        @Override
//        public Point getToolTipLocation( MouseEvent event ) {
//            Rectangle bounds = getBounds();
//            bounds.x += bounds.width;
//            bounds.y = 0;
//            return bounds.getLocation();
//        }
	}
}
