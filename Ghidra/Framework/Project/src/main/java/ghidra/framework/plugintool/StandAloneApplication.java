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
package ghidra.framework.plugintool;

import java.awt.Image;
import java.awt.Taskbar;
import java.io.*;
import java.util.List;

import javax.swing.ImageIcon;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import docking.framework.*;
import ghidra.framework.*;
import ghidra.framework.model.ToolServices;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;
import utility.application.ApplicationLayout;

public abstract class StandAloneApplication implements GenericStandAloneApplication {

	private static final String DEFAULT_TOOL_NAME = "DefaultTool.tool";
	private static final String SAVED_TOOL_FILE = "SavedTool.tool";
	private SettableApplicationInformationDisplayFactory displayFactory;
	protected ApplicationLayout layout;
	protected DockingApplicationConfiguration configuration;
	protected PluginTool tool;

	/**
	 * Creates a new application using the given properties filename. The
	 * filename is expected reside in the current working directory.
	 * <p>
	 * <b>The given properties file is expected to have the
	 * {@link ApplicationProperties#APPLICATION_NAME_PROPERTY} and
	 * {@link ApplicationProperties#APPLICATION_VERSION_PROPERTY} properties
	 * set.</b>
	 * 
	 * @param propertiesFilename the name of the properties file.
	 * @throws IOException error causing application initialization failure
	 */
	public StandAloneApplication(String propertiesFilename) throws IOException {
		this(new DockingApplicationLayout(readApplicationProperties(propertiesFilename)));
	}

	/**
	 * Creates a new application using the specified application name 
	 * and version.
	 * @param name application name
	 * @param version application version
	 * @throws IOException error causing application initialization failure
	 */
	public StandAloneApplication(String name, String version) throws IOException {
		this(new DockingApplicationLayout(name, version));
	}

	/**
	 * reates a new application using the given application layout
	 * and associated application properties.
	 * @param applicationLayout application layout
	 */
	public StandAloneApplication(ApplicationLayout applicationLayout) {
		init(applicationLayout);
	}

	/**
	 * Read {@link ApplicationProperties} from the specified file path relative
	 * to the current working directory.
	 * <p>
	 * <b>The given properties file is expected to have the
	 * {@link ApplicationProperties#APPLICATION_NAME_PROPERTY} and
	 * {@link ApplicationProperties#APPLICATION_VERSION_PROPERTY} properties
	 * set.</b>
	 * @param propertiesFilename the name of the properties file.
	 * @return application properties
	 * @throws IOException if file read error occurs
	 */
	public static ApplicationProperties readApplicationProperties(String propertiesFilename)
			throws IOException {
		ApplicationProperties properties = ApplicationProperties.fromFile(propertiesFilename);
		String name = properties.getProperty(ApplicationProperties.APPLICATION_NAME_PROPERTY);
		if (name == null) {
			Msg.error(StandAloneApplication.class,
				"The application.name property is not set in " + propertiesFilename);
		}

		String version = properties.getProperty(ApplicationProperties.APPLICATION_VERSION_PROPERTY);
		if (version == null) {
			Msg.error(StandAloneApplication.class,
				"The application.name property is not set in " + propertiesFilename);
		}
		return properties;
	}

	private void init(ApplicationLayout applicationLayout) {
		this.layout = applicationLayout;

		// Setup application configuration
		configuration = new DockingApplicationConfiguration();
		configuration.setShowSplashScreen(false);

		displayFactory = new SettableApplicationInformationDisplayFactory();
	}

	public void showSpashScreen(ImageIcon splashIcon) {
		configuration.setShowSplashScreen(true);
		displayFactory.setSplashIcon128(splashIcon);
	}

	public void setWindowsIcons(List<Image> windowsIcons) {
		displayFactory.setWindowsIcons(windowsIcons);
	}

	public void setHomeIcon(ImageIcon icon) {
		displayFactory.setHomeIcon(icon);
	}

	public void setHomeCallback(Runnable callback) {
		displayFactory.setHomeCallback(callback);
	}

	public void start() {
		PluggableServiceRegistry.registerPluggableService(
			ApplicationInformationDisplayFactory.class, displayFactory);

		Application.initializeApplication(layout, configuration);
		try {
			ClassSearcher.search(false, configuration.getTaskMonitor());
		}
		catch (CancelledException e) {
			Msg.debug(this, "Class searching unexpectedly cancelled.");
		}

		setDockIcon();

		try {
			SystemUtilities.runSwingNow(() -> tool = createTool());
		}
		catch (Exception e) {
			Msg.error(this, "Error creating tool, exiting...", e);
			System.exit(0);
		}

		showTool();
	}

	protected void showTool() {
		tool.setVisible(true);
	}

	private void setDockIcon() {
		if (Taskbar.isTaskbarSupported()) {
			Taskbar taskbar = Taskbar.getTaskbar();
			if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
				taskbar.setIconImage(ApplicationInformationDisplayFactory.getLargestWindowIcon());
			}
		}
	}

	protected PluginTool createTool() {
		StandAlonePluginTool newTool = new StandAlonePluginTool(StandAloneApplication.this,
			layout.getApplicationProperties().getApplicationName(), true);

		Element rootElement = getSavedToolElement();
		if (rootElement == null) {
			rootElement = getDefaultToolElement();
		}
		if (rootElement != null) {
			Element toolElement = rootElement.getChild("TOOL");
			Element savedDataElement = rootElement.getChild("DATA_STATE");
			configuration.getTaskMonitor().setMessage("Restoring Tool Configuration...");
			newTool.restoreFromXml(toolElement);
			configuration.getTaskMonitor().setMessage("Restoring Tool State...");
			newTool.restoreDataStateFromXml(savedDataElement);
		}

		initializeTool(newTool);
		return newTool;
	}

	protected void initializeTool(StandAlonePluginTool newTool) {
		newTool.addExitAction();
	}

	private Element getDefaultToolElement() {
		try {
			InputStream instream = ResourceManager.getResourceAsStream(DEFAULT_TOOL_NAME);
			if (instream == null) {
				return null;
			}

			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Element root = sax.build(instream).getRootElement();
			return root;
		}
		catch (Exception e) {
			Msg.showError(getClass(), null, "Error Reading Tool",
				"Could not read tool: " + DEFAULT_TOOL_NAME, e);
		}
		return null;
	}

	private Element getSavedToolElement() {
		File savedToolFile = new File(Application.getUserSettingsDirectory(), SAVED_TOOL_FILE);
		if (!savedToolFile.exists()) {
			return null;
		}

		FileInputStream fileInputStream = null;
		try {
			fileInputStream = new FileInputStream(savedToolFile.getAbsolutePath());
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Element root = sax.build(fileInputStream).getRootElement();
			return root;
		}
		catch (Exception e) {
			Msg.showError(getClass(), null, "Error Reading Tool",
				"Could not read tool: " + savedToolFile, e);
		}
		finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}

		return null;
	}

	@Override
	public void exit() {
		tool.close();
	}

	@Override
	public ToolServices getToolServices() {
		return new ToolServicesAdapter() {

			@Override
			public void closeTool(PluginTool t) {
				System.exit(0);
			}

			@Override
			public void saveTool(PluginTool saveTool) {
				Element toolElement = saveTool.saveToXml(true);
				Element dataStateElement = saveTool.saveDataStateToXml(false);
				Element rootElement = new Element("Root");
				rootElement.addContent(toolElement);
				rootElement.addContent(dataStateElement);
				File savedToolFile =
					new File(Application.getUserSettingsDirectory(), SAVED_TOOL_FILE);
				OutputStream os = null;
				try {
					os = new FileOutputStream(savedToolFile);
					Document doc = new Document(rootElement);
					XMLOutputter xmlout = new GenericXMLOutputter();
					xmlout.output(doc, os);
					os.close();
				}
				catch (Exception e) {
					Msg.error(this, "Error saving tool", e);
					try {
						if (os != null) {
							os.close();
						}
						savedToolFile.delete();
					}
					catch (Exception exc) {
						// cleanup, don't care
					}
				}

			}
		};
	}

}
