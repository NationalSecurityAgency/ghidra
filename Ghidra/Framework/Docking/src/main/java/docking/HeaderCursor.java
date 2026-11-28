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
import java.awt.dnd.DragSource;
import java.awt.image.BufferedImage;

import generic.theme.*;

/**
 * The cursor values used when drag-n-dropping dockable components
 */
public class HeaderCursor {

	private static final GColor CURSOR_COLOR = new GColor("color.header.drag.cursor");
	private static final ThemeListener THEME_LISTENER = event -> {
		if (event.isColorChanged(CURSOR_COLOR.getId())) {
			initilizeCursors();
		}
	};

	static Cursor LEFT;
	static Cursor RIGHT;
	static Cursor TOP;
	static Cursor BOTTOM;
	static Cursor STACK;
	static Cursor PREPEND;
	static Cursor PUSH;
	static Cursor SHIFT_LEFT;
	static Cursor SHIFT_RIGHT;
	static Cursor NEW_WINDOW;
	static Cursor NO_DROP = DragSource.DefaultMoveNoDrop;

	static {
		initilizeCursors();

		Gui.addThemeListener(THEME_LISTENER);
	}

	private static void initilizeCursors() {
		Toolkit tk = Toolkit.getDefaultToolkit();

		Image image = drawLeftArrow();
		LEFT = tk.createCustomCursor(image, new Point(0, 6), "LEFT");

		image = drawRightArrow();
		RIGHT = tk.createCustomCursor(image, new Point(31, 6), "RIGHT");

		image = drawTopArrow();
		TOP = tk.createCustomCursor(image, new Point(6, 0), "TOP");

		image = drawBottomArrow();
		BOTTOM = tk.createCustomCursor(image, new Point(6, 31), "BOTTOM");

		image = drawStack();
		STACK = tk.createCustomCursor(image, new Point(8, 8), "STACK");

		image = drawPrepend();
		PREPEND = tk.createCustomCursor(image, new Point(8, 8), "PREPEND");

		image = drawPush();
		PUSH = tk.createCustomCursor(image, new Point(6, 6), "PUSH");

		image = drawShiftLeft();
		SHIFT_LEFT = tk.createCustomCursor(image, new Point(6, 6), "SHIFT_LEFT");

		image = drawShiftRight();
		SHIFT_RIGHT = tk.createCustomCursor(image, new Point(6, 6), "SHIFT_RIGHT");

		image = drawNewWindow();
		NEW_WINDOW = tk.createCustomCursor(image, new Point(0, 0), "NEW_WINDOW");
	}

	private static Image drawLeftArrow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = CURSOR_COLOR.getRGB();
		int y = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(i, y - i + j, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(i, y - 1 + j, v);
			}
		}

		return image;
	}

	private static Image drawRightArrow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = CURSOR_COLOR.getRGB();
		int y = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(31 - i, y - i + j, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(31 - i, y - 1 + j, v);
			}
		}

		return image;
	}

	private static Image drawTopArrow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = CURSOR_COLOR.getRGB();
		int x = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(x - i + j, i, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(x - 1 + j, i, v);
			}
		}
		return image;
	}

	private static Image drawBottomArrow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = CURSOR_COLOR.getRGB();
		int x = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(x - i + j, 31 - i, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(x - 1 + j, 31 - i, v);
			}
		}
		return image;
	}

	private static Image drawStack() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		// highlight the target position in the stack
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int offset = 6;
		for (int x = 1; x < 10; x++) {
			for (int y = 1; y < 10; y++) {
				image.setRGB(x + offset, y, headerColor);
			}
		}
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 3; i++) {
			int x = i * 3;
			int y = 6 - i * 3;
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);
				image.setRGB(x + 10, y + j, v);
				image.setRGB(x + j, y, v);
				image.setRGB(x + j, y + 10, v);
			}
		}

		return image;
	}

	private static Image drawPrepend() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 3; i++) {
			int x = i * 3;
			int y = 6 - i * 3;
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);
				image.setRGB(x + 10, y + j, v);
				image.setRGB(x + j, y, v);
				image.setRGB(x + j, y + 10, v);
			}
		}
		// highlight the target position in the stack
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int offset = 6;
		for (int x = 1; x < 10; x++) {
			for (int y = 1; y < 10; y++) {
				image.setRGB(x, y + offset, headerColor);
			}
		}

		return image;
	}

	private static Image drawPush() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		// draw adjacent overlapping boxes
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 2; i++) {
			int x = i * 3;
			int y = i%2 != 0 ? 3 : 0;
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);
				image.setRGB(x + 10, y + j, v);
				image.setRGB(x + j, y, v);
				image.setRGB(x + j, y + 10, v);
			}
		}
		// highlight the target position in the stack
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int x_offset = 0;
		int y_offset = 0;
		for (int x = 1; x < 10; x++) {
			for (int y = 1; y < 10; y++) {
				image.setRGB(x + x_offset, y + y_offset, headerColor);
			}
		}

		return image;
	}

	private static Image drawShiftLeft() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		// highlight the target position in the stack
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int x_offset = 0;
		int y_offset = 3;
		for (int x = 1; x < 10; x++) {
			for (int y = 1; y < 10; y++) {
				image.setRGB(x + x_offset, y + y_offset, headerColor);
			}
		}
		// draw adjacent overlapping boxes
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 2; i++) {
			int x = i * 3;
			int y = i%2 == 0 ? 3 : 0;
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);
				image.setRGB(x + 10, y + j, v);
				image.setRGB(x + j, y, v);
				image.setRGB(x + j, y + 10, v);
			}
		}

		return image;
	}

	private static Image drawShiftRight() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		// highlight the target position in the stack
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int x_offset = 3;
		int y_offset = 3;
		for (int x = 1; x < 10; x++) {
			for (int y = 1; y < 10; y++) {
				image.setRGB(x + x_offset, y + y_offset, headerColor); // horizontal line
			}
		}
		// draw adjacent overlapping boxes
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 2; i++) {
			int x = i * 3;                      // concatenate moving by x offset
			int y = i%2 != 0 ? 3 : 0;           // alternate y higher and lower
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);      // left vertical line
				image.setRGB(x + 10, y + j, v); // right vertical line
				image.setRGB(x + j, y, v);      // top horizontal line
				image.setRGB(x + j, y + 10, v); // bottom horizontal line
			}
		}

		return image;
	}

	private static Image drawNewWindow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int headerColor = new GColor("color.bg.header.active").getRGB();
		int v = CURSOR_COLOR.getRGB();
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 14; j++) {
				image.setRGB(j, i, headerColor);
			}
		}
		for (int i = 0; i < 14; i++) {
			image.setRGB(i, 0, v);
			image.setRGB(i, 10, v);
		}
		for (int i = 0; i < 10; i++) {
			image.setRGB(0, i, v);
			image.setRGB(14, i, v);
		}
		return image;
	}
}
