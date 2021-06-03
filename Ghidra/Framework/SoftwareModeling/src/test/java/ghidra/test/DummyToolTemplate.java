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
package ghidra.test;

import javax.swing.ImageIcon;

import org.jdom.Element;

import docking.util.image.ToolIconURL;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class DummyToolTemplate implements ToolTemplate {

	@Override
	public PluginTool createTool(Project project) {
		return new DummyTool(project);
	}

	@Override
	public ImageIcon getIcon() {
		return null;
	}

	@Override
	public ToolIconURL getIconURL() {
		return null;
	}

	@Override
	public String getName() {
		return "Dummy Tool";
	}

	@Override
	public String getPath() {
		return "/dummy";
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { Program.class };
	}

	@Override
	public Element getToolElement() {
		return null;
	}

	@Override
	public void restoreFromXml(Element root) {
		// stub
	}

	@Override
	public Element saveToXml() {
		return null;
	}

	@Override
	public void setName(String name) {
		// stub
	}
}
