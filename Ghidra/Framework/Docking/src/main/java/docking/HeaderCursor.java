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

/**
 * The cursor values used when drag-n-dropping dockable components
 */
public class HeaderCursor {

	static Cursor LEFT;
	static Cursor RIGHT;
	static Cursor TOP;
	static Cursor BOTTOM;
	static Cursor STACK;
	static Cursor NEW_WINDOW;
	static Cursor NO_DROP = DragSource.DefaultMoveNoDrop;

	static {
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

		image = drawNewWindow();
		NEW_WINDOW = tk.createCustomCursor(image, new Point(0, 0), "NEW_WINDOW");
	}

	private static Image drawLeftArrow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = 0xff000000;
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
		int v = 0xff000000;
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
		int v = 0xff000000;
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
		int v = 0xff000000;
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
		int v = 0xff000000;
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

	private static Image drawNewWindow() {

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		int v = 0xff000000;
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 14; j++) {
				image.setRGB(j, i, 0xff0000ff);
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
