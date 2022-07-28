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
package docking.theme.laf;

import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import ghidra.docking.util.LookAndFeelUtils;
import ghidra.util.Msg;

public class GenericLookAndFeelInstaller extends LookAndFeelInstaller {
	private String name;

	public GenericLookAndFeelInstaller(String name) {
		this.name = name;
	}

	@Override
	protected void installLookAndFeel() throws Exception {
		String className = findLookAndFeelClassName(name);
		UIManager.setLookAndFeel(className);
	}

	private static String findLookAndFeelClassName(String lookAndFeelName) {
		if (lookAndFeelName.equalsIgnoreCase(LookAndFeelUtils.SYSTEM_LOOK_AND_FEEL)) {
			return UIManager.getSystemLookAndFeelClassName();
		}

		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			String className = info.getClassName();
			if (lookAndFeelName.equals(className) || lookAndFeelName.equals(info.getName())) {
				return className;
			}
		}

		Msg.debug(LookAndFeelUtils.class,
			"Unable to find requested Look and Feel: " + lookAndFeelName);
		return UIManager.getSystemLookAndFeelClassName();
	}

}
