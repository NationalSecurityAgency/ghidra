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
package ghidra.framework.analysis.gui;

import javax.swing.Icon;

import ghidra.app.services.AnalyzerType;
import ghidra.util.exception.AssertException;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class AnalyzerUtil {
	private static final Icon BYTES_ICON = ResourceManager.loadImage("images/mem_chip3.png");
	private static final Icon DATA_ICON = ResourceManager.loadImage("images/Data_32.png");

	private static final Icon FUNCTION_ICON = new MultiIcon(ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/FunctionScope.gif"), 28, 28), false, 32, 32);
	private static final Icon FUNCTION_MODIFIER_ICON = getIconForFunctionModifiersChanged();
	private static final Icon FUNCTION_SIGNATURE_ICON = getIconForFunctionSignatureChanged();

	private static final Icon INSTRUCTION_ICON =
		ResourceManager.loadImage("images/Instructions_32.png");
	private static final Icon MANUAL_ICON = new MultiIcon(
		new TranslateIcon(ResourceManager.loadImage("images/play.png"), 5, 5), false, 32, 32);

	private static Icon getIconForFunctionModifiersChanged() {
		Icon baseIcon = new TranslateIcon(ResourceManager.getScaledIcon(
			ResourceManager.loadImage("images/FunctionScope.gif"), 22, 22), 10, 5);
		Icon hammerIcon = ResourceManager.loadImage("images/applications-development16.png");
		MultiIcon multiIcon = new MultiIcon(baseIcon, false, 32, 32);
		multiIcon.addIcon(hammerIcon);
		return multiIcon;
	}

	private static Icon getIconForFunctionSignatureChanged() {
		Icon baseIcon = new TranslateIcon(ResourceManager.getScaledIcon(
			ResourceManager.loadImage("images/FunctionScope.gif"), 22, 22), 10, 5);
		Icon pencilIcon = ResourceManager.loadImage("images/pencil.png");
		MultiIcon multiIcon = new MultiIcon(baseIcon, false, 32, 32);
		multiIcon.addIcon(pencilIcon);
		return multiIcon;
	}

	public static Icon getIcon(AnalyzerType type) {
		switch (type) {
			case BYTE_ANALYZER:
				return BYTES_ICON;
			case DATA_ANALYZER:
				return DATA_ICON;
			case FUNCTION_ANALYZER:
				return FUNCTION_ICON;
			case FUNCTION_MODIFIERS_ANALYZER:
				return FUNCTION_MODIFIER_ICON;
			case FUNCTION_SIGNATURES_ANALYZER:
				return FUNCTION_SIGNATURE_ICON;
			case INSTRUCTION_ANALYZER:
				return INSTRUCTION_ICON;
			case ONE_SHOT_ANALYZER:
				return MANUAL_ICON;
			default:
				throw new AssertException("Missing case statement for icons");

		}
	}
}
