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
package ghidra.docking.util;

import java.awt.Color;

import ghidra.docking.util.DockingWindowsLookAndFeelUtils;

public interface ColorContext {
    // isAuto indicates that we should let the LAF pick the colors, instead of using the hard-coded values
    final boolean isAuto = DockingWindowsLookAndFeelUtils.isUsingFlatUI();
    // isDark indicates that we're currently using a dark mode LAF
    final boolean isDark = DockingWindowsLookAndFeelUtils.isUsingFlatDarkUI();

    final Color WHITE = isDark ? new Color(197, 200, 198) : Color.WHITE;
    final Color RED = isDark ? new Color(237, 89, 64) : Color.RED;
    final Color DARK_GRAY = isDark ? Color.LIGHT_GRAY : Color.DARK_GRAY;
    final Color LIGHT_GRAY = isDark ? Color.DARK_GRAY : Color.LIGHT_GRAY;
    final Color GRAY = Color.GRAY;
    final Color BLACK = isDark ? WHITE : Color.BLACK;
    final Color ORANGE = isDark ? new Color(243, 164, 46) : Color.ORANGE;
    final Color BLUE = isDark ? new Color(58, 132, 250) : Color.BLUE;
    final Color GREEN = isDark ? new Color(105, 210, 88) : Color.GREEN;
    final Color MAGENTA = isDark ? new Color(179, 101, 238) : Color.MAGENTA;

    final Color DARK_HIGHLIGHT_FOREGROUND = new Color(86, 88, 91);
    final Color DARK_HIGHLIGHT_BACKGROUND = new Color(55, 59, 65);

    final Color BACKGROUND = isDark ? new Color(40, 42, 46) : Color.WHITE;
    final Color SELECTION_SELECTION = isDark ? DARK_HIGHLIGHT_FOREGROUND : new Color(180, 255, 180);
    final Color SELECTION_HIGHLIGHT = isDark ? DARK_HIGHLIGHT_FOREGROUND : new Color(255, 255, 180);
    final Color SELECTION_DIFFERENCE = isDark ? DARK_HIGHLIGHT_FOREGROUND : new Color(255, 230, 180); // light orange
    final Color CURSOR_HIGHLIGHT = isDark ? DARK_HIGHLIGHT_FOREGROUND : new Color(255, 255, 180);
    final Color CURSOR_LINE = isDark ? DARK_HIGHLIGHT_BACKGROUND : new Color(232, 242, 254);
    final Color CURSOR_TEXT_HIGHLIGHT = isDark ? DARK_HIGHLIGHT_BACKGROUND : Color.YELLOW;
    final Color CURSOR_TEXT_SCOPED_WRITE_HIGHLIGHT = isDark ? DARK_HIGHLIGHT_BACKGROUND : new Color(204, 204, 0);
    final Color CURSOR_TEXT_SCOPED_READ_HIGHLIGHT = isDark ? DARK_HIGHLIGHT_BACKGROUND : new Color(0, 255, 0);
    final Color CURSOR_FOCUSED = isDark ? new Color(197, 200, 198) : Color.RED;
    final Color CURSOR_UNFOCUSED = isDark ? new Color(55, 59, 65) : Color.PINK;
}