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

import java.awt.event.*;
import java.util.*;

import javax.swing.AbstractAction;
import javax.swing.KeyStroke;

import docking.action.DockingActionIf;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;

/**
 * A class that can be used as an interface for using actions associated with keybindings.  This
 * class is meant to only by used by internal Ghidra key event processing.
 */
public class DockingKeyBindingAction extends AbstractAction {

	private static final String RELEASED = "released";
	private static final String TYPED = "typed";
	private static final String PRESSED = "pressed";

	private static final String SHIFT = "Shift";
	private static final String CTRL = "Ctrl";
	private static final String CONTROL = "Control";
	private static final String ALT = "Alt";
	private static final String META = "Meta";
	private static final String MODIFIER_SEPARATOR = "-";

	private DockingActionIf docakbleAction;

	protected KeyStroke keyStroke;
	protected final DockingWindowManager winMgr;

	public DockingKeyBindingAction(DockingWindowManager winMgr, DockingActionIf action,
			KeyStroke keyStroke) {
		super(parseKeyStroke(keyStroke));
		this.winMgr = winMgr;
		this.docakbleAction = action;
		this.keyStroke = keyStroke;
	}

	KeyStroke getKeyStroke() {
		return keyStroke;
	}

	@Override
	public boolean isEnabled() {
		// always enable; this is a reserved binding and cannot be disabled
		return true;
	}

	public boolean isReservedKeybindingPrecedence() {
		return getKeyBindingPrecedence() == KeyBindingPrecedence.ReservedActionsLevel;
	}

	public KeyBindingPrecedence getKeyBindingPrecedence() {
		return KeyBindingPrecedence.ReservedActionsLevel;
	}

	@Override
	public void actionPerformed(final ActionEvent e) {
		winMgr.setStatusText("");
		ComponentProvider provider = winMgr.getActiveComponentProvider();
		ActionContext context = getLocalContext(provider);
		context.setSource(e.getSource());
		docakbleAction.actionPerformed(context);
	}

	protected ActionContext getLocalContext(ComponentProvider localProvider) {
		if (localProvider == null) {
			return new ActionContext();
		}

		ActionContext actionContext = localProvider.getActionContext(null);
		if (actionContext != null) {
			return actionContext;
		}

		return new ActionContext(localProvider, null);
	}

	/**
	 * Convert the toString() form of the keyStroke.
	 * <br>In Java 1.4.2 & earlier, Ctrl-M is returned as "keyCode CtrlM-P"
	 * and we want it to look like: "Ctrl-M".
	 * <br>In Java 1.5.0, Ctrl-M is returned as "ctrl pressed M"
	 * and we want it to look like: "Ctrl-M".
	 */
	public static String parseKeyStroke(KeyStroke keyStroke) {
		final String keyPressSuffix = "-P";

		String keyString = keyStroke.toString();
		int type = keyStroke.getKeyEventType();
		if (type == KeyEvent.KEY_TYPED) {
			return String.valueOf(keyStroke.getKeyChar());
		}

		// get the character used in the key stroke
		int firstIndex = keyString.lastIndexOf(' ') + 1;
		int ctrlIndex = keyString.indexOf(CTRL, firstIndex);
		if (ctrlIndex >= 0) {
			firstIndex = ctrlIndex + CTRL.length();
		}
		int altIndex = keyString.indexOf(ALT, firstIndex);
		if (altIndex >= 0) {
			firstIndex = altIndex + ALT.length();
		}
		int shiftIndex = keyString.indexOf(SHIFT, firstIndex);
		if (shiftIndex >= 0) {
			firstIndex = shiftIndex + SHIFT.length();
		}
		int metaIndex = keyString.indexOf(META, firstIndex);
		if (metaIndex >= 0) {
			firstIndex = metaIndex + META.length();
		}

		int lastIndex = keyString.length();
		if (keyString.endsWith(keyPressSuffix)) {
			lastIndex -= keyPressSuffix.length();
		}
		if (lastIndex >= 0) {
			keyString = keyString.substring(firstIndex, lastIndex);
		}

		int modifiers = keyStroke.getModifiers();

		StringBuffer buffer = new StringBuffer();
		if ((modifiers & InputEvent.SHIFT_MASK) != 0) {
			buffer.insert(0, SHIFT + MODIFIER_SEPARATOR);
		}
		if ((modifiers & InputEvent.ALT_MASK) != 0) {
			buffer.insert(0, ALT + MODIFIER_SEPARATOR);
		}
		if ((modifiers & InputEvent.CTRL_MASK) != 0) {
			buffer.insert(0, CTRL + MODIFIER_SEPARATOR);
		}
		if ((modifiers & InputEvent.META_MASK) != 0) {
			buffer.insert(0, META + MODIFIER_SEPARATOR);
		}
		buffer.append(keyString);
		return buffer.toString();
	}

	/**
	 * Parses the given text into a KeyStroke.  This method relies upon 
	 * {@link KeyStroke#getKeyStroke(String)} for parsing.  Before making that call, this method
	 * will perform fixup on the given text for added flexibility.  For example, the given 
	 * text may contain spaces or dashes as the separators between parts in the string.  Also, 
	 * the text is converted such that it is not case-sensitive.  So, the following example 
	 * formats are allowed:
	 * <pre>
	 *    Alt-F
	 *    alt p
	 *    Ctrl-Alt-Z
	 *    ctrl Z
	 * </pre>  
	 * 
	 * @param keyStroke
	 * @return
	 */
	public static KeyStroke parseKeyStroke(String keyStroke) {
		List<String> pieces = new ArrayList<>();
		StringTokenizer tokenizer = new StringTokenizer(keyStroke, "- ");
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			if (!pieces.contains(token)) {
				pieces.add(token);
			}
		}

		StringBuffer keyStrokeBuff = new StringBuffer();
		for (Iterator<String> iterator = pieces.iterator(); iterator.hasNext();) {
			String piece = iterator.next();
			if (StringUtilities.indexOfIgnoreCase(piece, SHIFT) != -1) {
				keyStrokeBuff.append("shift ");
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, CTRL) != -1) {
				keyStrokeBuff.append("ctrl ");
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, CONTROL) != -1) {
				keyStrokeBuff.append("ctrl ");
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, ALT) != -1) {
				keyStrokeBuff.append("alt ");
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, META) != -1) {
				keyStrokeBuff.append("meta ");
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, PRESSED) != -1) {
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, TYPED) != -1) {
				iterator.remove();
			}
			else if (StringUtilities.indexOfIgnoreCase(piece, RELEASED) != -1) {
				iterator.remove();
			}

		}

		keyStrokeBuff.append(PRESSED).append(' ');

		// at this point we should only have left one piece--the key ID
		int leftover = pieces.size();
		if (leftover > 1 || leftover == 0) {
			Msg.warn(DockingKeyBindingAction.class, "Invalid keystroke string found.  Expected " +
				"format of '[modifier] ... key'.  Found: '" + keyStroke + "'");

			if (leftover == 0) {
				return null; // nothing to do
			}
		}

		String key = pieces.get(0);
		keyStrokeBuff.append(key.toUpperCase());

		return KeyStroke.getKeyStroke(keyStrokeBuff.toString());
	}
}
