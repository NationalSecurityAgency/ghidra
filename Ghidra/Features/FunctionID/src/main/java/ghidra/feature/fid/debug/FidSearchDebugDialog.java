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
package ghidra.feature.fid.debug;

import java.io.IOException;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.plugin.FidPlugin;
import ghidra.feature.fid.service.FidService;
import ghidra.util.HelpLocation;
import ghidra.util.exception.VersionException;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for searching Fid Databases for debug purposes.  Entering data in any of the fields
 * in this dialog will search the database for all records that match any fields that
 * have data in them and then display the results in a table.
 */
public class FidSearchDebugDialog extends DialogComponentProvider {
	private FidService service;
	private FidQueryService fidQueryService;
	private JTextField functionIdTextField;
	private JTextField nameTextField;
	private JTextField pathTextField;
	private JTextField fhTextField;
	private JTextField xhTextField;

	public FidSearchDebugDialog(FidService service) throws VersionException, IOException {
		super("Fid Db Search", false);
		this.service = service;
		addDismissButton();
		addWorkPanel(buildPanel());
		fidQueryService = FidFileManager.getInstance().openFidQueryService(null, true);
		setRememberSize(false);
		setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "debugsearch"));
	}

	public void setFunctionIdText(String id) {
		functionIdTextField.setText(id);
	}

	public void setNameText(String name) {
		nameTextField.setText(name);
	}

	public void setDomainPathText(String path) {
		pathTextField.setText(path);
	}

	public void setFullHashText(String hash) {
		fhTextField.setText(hash);
	}

	public void setSpecificHashText(String hash) {
		xhTextField.setText(hash);
	}

	private JLabel getPreparedLabel(String text) {
		JLabel label = new GDLabel(text, SwingConstants.RIGHT);
		label.setFont(FidDebugUtils.MONOSPACED_FONT);
		return label;
	}

	private JTextField getPreparedTextField() {
		JTextField textField = new JTextField(25);
		textField.setFont(FidDebugUtils.MONOSPACED_FONT);
		return textField;
	}

	private JComponent buildPanel() {
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.setLayout(new PairLayout(5, 5));

		panel.add(getPreparedLabel("Function ID: "));
		functionIdTextField = getPreparedTextField();
		panel.add(functionIdTextField);

		panel.add(getPreparedLabel("Name: "));
		nameTextField = getPreparedTextField();
		panel.add(nameTextField);

		panel.add(getPreparedLabel("Domain Path: "));
		pathTextField = getPreparedTextField();
		panel.add(pathTextField);

		panel.add(getPreparedLabel("FH: "));
		fhTextField = getPreparedTextField();
		panel.add(fhTextField);

		panel.add(getPreparedLabel("XH: "));
		xhTextField = getPreparedTextField();
		panel.add(xhTextField);

		functionIdTextField.addActionListener(e -> {
			String text = ((JTextField) e.getSource()).getText();
			Long val = FidDebugUtils.validateHashText(text, "function ID");
			if (val == null) {
				return;
			}
			FidDebugUtils.searchByFunctionID(val.longValue(), service, fidQueryService);
		});
		nameTextField.addActionListener(e -> {
			String text = ((JTextField) e.getSource()).getText();
			FidDebugUtils.searchByName(text, service, fidQueryService);
		});
		pathTextField.addActionListener(e -> {
			String text = ((JTextField) e.getSource()).getText();
			FidDebugUtils.searchByDomainPath(text, service, fidQueryService);

		});
		fhTextField.addActionListener(e -> {
			String text = ((JTextField) e.getSource()).getText();
			Long val = FidDebugUtils.validateHashText(text, "full hash");
			if (val == null) {
				return;
			}
			FidDebugUtils.searchByFullHash(val.longValue(), service, fidQueryService);
		});
		xhTextField.addActionListener(e -> {
			String text = ((JTextField) e.getSource()).getText();
			Long val = FidDebugUtils.validateHashText(text, "specific hash");
			if (val == null) {
				return;
			}
			FidDebugUtils.searchBySpecificHash(val.longValue(), service, fidQueryService);

		});
		return panel;
	}

	@Override
	public void close() {
		fidQueryService.close();
		super.close();
	}
}
