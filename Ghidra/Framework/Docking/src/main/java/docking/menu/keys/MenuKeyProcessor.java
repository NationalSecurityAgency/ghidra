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
package docking.menu.keys;

import java.awt.event.KeyEvent;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

/**
 * Handles the processing of key events while menus or popup menus are open.
 */
public class MenuKeyProcessor {

	private static Map<KeyStroke, MenuKeyHandler> menuHandlersByKeyStroke = new HashMap<>();

	static {

		menuHandlersByKeyStroke.put(keyStroke("HOME"), new HomeMenuKeyHandler());
		menuHandlersByKeyStroke.put(keyStroke("END"), new EndMenuKeyHandler());
		menuHandlersByKeyStroke.put(keyStroke("PAGE_UP"), new PageUpMenuKeyHandler());
		menuHandlersByKeyStroke.put(keyStroke("PAGE_DOWN"), new PageDownMenuKeyHandler());

		for (int i = 1; i < 10; i++) {
			menuHandlersByKeyStroke.put(keyStroke(Integer.toString(i)),
				new NumberMenuKeyHandler(i));
		}
	}

	/**
	 * Checks the given event to see if it has a registered action to perform while a menu is open.
	 * If a menu is open and a handler exists, the handler will be called.
	 * 
	 * @param event the event to check
	 * @return true if the event triggered a handler
	 */
	public static boolean processMenuKeyEvent(KeyEvent event) {

		MenuSelectionManager manager = MenuSelectionManager.defaultManager();
		MenuElement[] path = manager.getSelectedPath();
		if (path == null || path.length == 0) {
			return false; // no menu showing
		}

		KeyStroke eventStroke = KeyStroke.getKeyStrokeForEvent(event);
		MenuKeyHandler Handler = menuHandlersByKeyStroke.get(eventStroke);
		if (Handler != null) {
			Handler.process(manager, path);
			event.consume();
			return true;
		}

		return false;
	}

	private static KeyStroke keyStroke(String s) {
		return KeyStroke.getKeyStroke("pressed " + s);
	}

}
