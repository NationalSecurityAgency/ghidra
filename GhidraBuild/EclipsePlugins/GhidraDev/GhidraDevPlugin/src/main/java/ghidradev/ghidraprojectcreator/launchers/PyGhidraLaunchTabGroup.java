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
package ghidradev.ghidraprojectcreator.launchers;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.debug.core.ILaunchConfigurationWorkingCopy;
import org.eclipse.debug.ui.*;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;
import org.python.pydev.debug.ui.*;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraLaunchUtils;

/**
 * The PyGhidra launcher tab group with default values needed for running/debugging
 * PyGhidra. Some Python tabs are hidden here because we don't want the user changing their 
 * properties. These properties are set in {@link PyGhidraLaunchDelegate}, which occurs right before
 * the launch.
 */
public class PyGhidraLaunchTabGroup extends PythonTabGroup {

	@Override
	public void createTabs(ILaunchConfigurationDialog dialog, String mode) {

		// Create the tabs
		List<ILaunchConfigurationTab> tabs = new ArrayList<>();
		tabs.add(getMainModuleTab());
		tabs.add(getUserDefinedArgumentsTab());
		tabs.add(getInterpreterTab());
		tabs.add(new EnvironmentTab());
		tabs.add(getCommonTab());

		// Set the tabs
		setTabs(tabs.toArray(new ILaunchConfigurationTab[tabs.size()]));
	}

	/**
	 * Gets the {@link MainModuleTab} to use, with PyGhidra's main module pre-configured in.
	 * 
	 * @return The {@link MainModuleTab} to use, with Ghidra's main method pre-configured in.
	 */
	private MainModuleTab getMainModuleTab() {
		return new MainModuleTab() {
			@Override
			public void initializeFrom(ILaunchConfiguration config) {
				try {
					ILaunchConfigurationWorkingCopy wc = config.getWorkingCopy();
					GhidraLaunchUtils.setMainTypeName(wc);
					super.initializeFrom(wc.doSave());
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to initialize the Python main module tab.",
						e);
				}
			}
		};
	}

	/**
	 * Gets the user-defined arguments to use.  These will be appended to PyGhidra's required
	 * launch arguments, which are hidden from the tab group.
	 * 
	 * @return The user-defined arguments to use.
	 */
	private AbstractLaunchConfigurationTab getUserDefinedArgumentsTab() {
		return new AbstractLaunchConfigurationTab() {

			private Text programArgsText;
			private Text vmArgsText;

			@Override
			public void createControl(Composite parent) {
				Composite container = new Composite(parent, SWT.NONE);
				container.setLayout(new GridLayout(1, true));
				GridData gd = new GridData(GridData.FILL_BOTH);
				container.setLayoutData(gd);

				// Program arguments
				Group group = new Group(container, SWT.NONE);
				group.setLayout(new GridLayout());
				group.setLayoutData(new GridData(GridData.FILL_BOTH));
				group.setText("Program arguments:");
				programArgsText = new Text(group, SWT.MULTI | SWT.WRAP | SWT.BORDER | SWT.V_SCROLL);
				gd = new GridData(GridData.FILL_BOTH);
				gd.heightHint = 40;
				gd.widthHint = 100;
				programArgsText.setLayoutData(gd);
				programArgsText.addModifyListener(evt -> scheduleUpdateJob());

				// VM arguments
				group = new Group(container, SWT.NONE);
				group.setLayout(new GridLayout());
				group.setLayoutData(new GridData(GridData.FILL_BOTH));
				group.setText("VM arguments (appended to arguments defined in launch.properties):");
				vmArgsText = new Text(group, SWT.MULTI | SWT.WRAP | SWT.BORDER | SWT.V_SCROLL);
				gd = new GridData(GridData.FILL_BOTH);
				gd.heightHint = 40;
				gd.widthHint = 100;
				vmArgsText.setLayoutData(gd);
				vmArgsText.addModifyListener(evt -> scheduleUpdateJob());

				setControl(container);
			}

			@Override
			public void setDefaults(ILaunchConfigurationWorkingCopy config) {
				try {
					ILaunchConfigurationWorkingCopy wc = config.getWorkingCopy();
					wc.setAttribute(GhidraLaunchUtils.ATTR_PROGAM_ARGUMENTS, "");
					wc.setAttribute(GhidraLaunchUtils.ATTR_VM_ARGUMENTS, "");
					wc.doSave();
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to set argument defaults.", e);
				}
			}

			@Override
			public void initializeFrom(ILaunchConfiguration config) {
				try {
					programArgsText.setText(
						config.getAttribute(GhidraLaunchUtils.ATTR_PROGAM_ARGUMENTS, ""));
					vmArgsText.setText(
						config.getAttribute(GhidraLaunchUtils.ATTR_VM_ARGUMENTS, ""));
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to initialize the arguments.", e);
				}
			}

			@Override
			public void performApply(ILaunchConfigurationWorkingCopy config) {
				try {
					ILaunchConfigurationWorkingCopy wc = config.getWorkingCopy();
					wc.setAttribute(GhidraLaunchUtils.ATTR_PROGAM_ARGUMENTS,
						programArgsText.getText());
					wc.setAttribute(GhidraLaunchUtils.ATTR_VM_ARGUMENTS, vmArgsText.getText());
					wc.doSave();
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to apply the arguments.", e);
				}
			}

			@Override
			public String getName() {
				return "Arguments";
			}
		};
	}

	/**
	 * Gets the {@link InterpreterTab} to use
	 * 
	 * @return The {@link InterpreterTab} to use
	 */
	private InterpreterTab getInterpreterTab() {
		return new InterpreterTab() {
			@Override
			public void initializeFrom(ILaunchConfiguration config) {
				try {
					ILaunchConfigurationWorkingCopy wc = config.getWorkingCopy();
					GhidraLaunchUtils.setClasspath(wc);
					super.initializeFrom(wc.doSave());
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to initialize the Python interpreter tab.",
						e);
				}
			}
		};
	}

	/**
	 * Gets the {@link CommonTab} to use, with the new launch configuration added to the favorites.
	 * 
	 * @return The {@link CommonTab} to use, with the new launch configuration added to the 
	 *   favorites.
	 */
	private CommonTab getCommonTab() {
		return new CommonTab() {
			@Override
			public void initializeFrom(ILaunchConfiguration config) {
				try {
					ILaunchConfigurationWorkingCopy wc = config.getWorkingCopy();
					GhidraLaunchUtils.setFavorites(wc);
					super.initializeFrom(wc.doSave());
				}
				catch (CoreException e) {
					EclipseMessageUtils.error("Failed to initialize the common tab.", e);
				}
			}
		};
	}
}
