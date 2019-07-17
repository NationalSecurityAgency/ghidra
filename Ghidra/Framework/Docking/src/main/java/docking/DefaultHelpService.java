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

import javax.swing.JButton;

import docking.help.HelpDescriptor;
import docking.help.HelpService;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class DefaultHelpService implements HelpService {

	@Override
	public void showHelp(Object helpObj, boolean infoOnly, Component parent) {
		if (infoOnly) {
			displayHelpInfo(helpObj);
			return;
		}
	}

	@Override
	public void showHelp(java.net.URL url) {
		// no-op
	}

	@Override
	public void excludeFromHelp(Object helpObject) {
		// no-op
	}

	@Override
	public boolean isExcludedFromHelp(Object helpObject) {
		return false;
	}

	@Override
	public void clearHelp(Object helpObject) {
		// no-op
	}

	@Override
	public void registerHelp(Object helpObj, HelpLocation helpLocation) {
		// no-op
	}

	@Override
	public HelpLocation getHelpLocation(Object object) {
		return null;
	}

	@Override
	public boolean helpExists() {
		return false;
	}

	private void displayHelpInfo(Object helpObj) {
		String msg = getHelpInfo(helpObj);
		Msg.showInfo(this, null, "Help Info", msg);
	}

	private String getHelpInfo(Object helpObj) {
		if (helpObj == null) {
			return "Help Object is null";
		}
		StringBuilder buffy = new StringBuilder();
		buffy.append("HELP OBJECT: " + helpObj.getClass().getName());
		buffy.append("\n");
		if (helpObj instanceof HelpDescriptor) {
			HelpDescriptor helpDescriptor = (HelpDescriptor) helpObj;
			buffy.append(helpDescriptor.getHelpInfo());

		}
		else if (helpObj instanceof JButton) {
			JButton button = (JButton) helpObj;
			buffy.append("   BUTTON: " + button.getText());
			buffy.append("\n");
			Component c = button;
			while (c != null && !(c instanceof Window)) {
				c = c.getParent();
			}
			if (c instanceof Dialog) {
				buffy.append("   DIALOG: " + ((Dialog) c).getTitle());
				buffy.append("\n");
			}
			if (c instanceof Frame) {
				buffy.append("   FRAME: " + ((Frame) c).getTitle());
				buffy.append("\n");
			}
		}
		return buffy.toString();
	}
}
