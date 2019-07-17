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
package ghidra.app.plugin.core.editor;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.TextEditorService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JOptionPane;

import docking.widgets.OptionDialog;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Generic Text Editor",
	description = "Provides a service to opening and editing text files.",
	servicesProvided = { TextEditorService.class }
)
//@formatter:on
public class TextEditorManagerPlugin extends ProgramPlugin implements TextEditorService {

	private List<TextEditorComponentProvider> editors = new ArrayList<>();

	public TextEditorManagerPlugin(PluginTool tool) {
		super(tool, true, true, true);
	}

	@Override
	public void edit(String name, InputStream inputStream) {
		try {
			TextEditorComponentProvider provider = new TextEditorComponentProvider( this, name, inputStream );
			editors.add( provider );
			tool.showComponentProvider( provider, true );
		}
		catch (IOException e) {
			JOptionPane.showMessageDialog( null, "Unable to edit " + name + " due to I/O error.", "Edit", JOptionPane.ERROR_MESSAGE );
		}
	}

	public List<TextEditorComponentProvider> getEditors() {
    	return editors;
    }

	public boolean removeTextFile(TextEditorComponentProvider editor, String textFileName) {
        if ( editor.isChanged() ) {
            JComponent parentComponent = editor.getComponent();
            if ( tool.isVisible( editor ) ) {
            	parentComponent = editor.getComponent();
            }
			int result = OptionDialog.showYesNoDialog( parentComponent, getName(),
        					"'"+textFileName+"' has been modified. Discard changes?");
            if (result != OptionDialog.OPTION_ONE) {
                return false;
            }
        }
        tool.removeComponentProvider( editor );
        editors.remove( editor );
        return true;
	}

}
