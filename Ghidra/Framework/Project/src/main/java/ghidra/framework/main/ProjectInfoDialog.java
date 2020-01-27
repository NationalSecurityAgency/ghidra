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
package ghidra.framework.main;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.File;
import java.io.IOException;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.DialogComponentProvider;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.OptionDialog;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.wizard.WizardManager;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.*;
import ghidra.framework.data.ConvertFileSystem;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.framework.store.local.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Dialog to show project information. Allows the user to convert a local project to a shared project,
 * OR to specify a different server or port, or repository for a shared project.
 *
 */
public class ProjectInfoDialog extends DialogComponentProvider {

	private final static Icon CONVERT_ICON = ResourceManager.loadImage("images/wand.png");
	public final static String CHANGE = "Change Shared Project Info...";
	final static String CONVERT = "Convert to Shared...";

	private FrontEndPlugin plugin;
	private Project project;
	private RepositoryAdapter repository;
	private JButton connectionButton;
	private JLabel userAccessLabel;
	private JButton changeConvertButton;
	private JButton convertStorageButton;
	private JLabel projectDirLabel;
	private JLabel serverLabel;
	private JLabel portLabel;
	private JLabel repNameLabel;

	ProjectInfoDialog(FrontEndPlugin plugin) {
		super("Project Information", false, true, true, false);
		this.plugin = plugin;
		project = plugin.getActiveProject();
		repository = project.getRepository();
		addWorkPanel(buildMainPanel());
		addDismissButton();
		setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END,
			repository != null ? "View_Project_Info" : "Convert_to_Shared"));
		setFocusComponent(dismissButton);
		setRememberSize(false);
	}

	/**
	 * Called from the project action manager when the connection state changes on the
	 * repository.
	 */
	void updateConnectionStatus() {
		boolean isConnected = repository.isConnected();
		connectionButton.setIcon(
			isConnected ? FrontEndPlugin.CONNECTED_ICON : FrontEndPlugin.DISCONNECTED_ICON);

		connectionButton.setContentAreaFilled(false);
		connectionButton.setSelected(isConnected);
		connectionButton.setBorder(
			isConnected ? BorderFactory.createBevelBorder(BevelBorder.LOWERED)
					: BorderFactory.createBevelBorder(BevelBorder.RAISED));
		updateConnectButtonToolTip();
		if (isConnected) {
			try {
				User user = repository.getUser();
				userAccessLabel.setText(getAccessString(user));
			}
			catch (IOException e) {
				Msg.error(this, "Exception obtaining user", e);
			}
		}
	}

	private JPanel buildMainPanel() {

		JPanel mainPanel = new JPanel(new VerticalLayout(20));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));
		mainPanel.add(buildInfoPanel());
		mainPanel.add(buildRepositoryInfoPanel());
		mainPanel.add(buildButtonPanel());

		return mainPanel;
	}

	private JPanel buildInfoPanel() {

		File dir = project.getProjectLocator().getProjectDir();

		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.setBorder(BorderFactory.createTitledBorder("Project Location"));

		JPanel infoPanel = new JPanel(new PairLayout(5, 10));
		infoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JLabel dirLabel = new GLabel("Directory Location:", SwingConstants.RIGHT);
		dirLabel.setToolTipText("Directory where your project files reside.");
		infoPanel.add(dirLabel);
		projectDirLabel = new GDLabel(dir.getAbsolutePath());
		infoPanel.add(projectDirLabel);

		infoPanel.add(new GLabel("Project Storage Type:", SwingConstants.RIGHT));
		Class<? extends LocalFileSystem> fsClass = project.getProjectData().getLocalStorageClass();
		String fsClassName = "<UNKNOWN>";
		if (IndexedV1LocalFileSystem.class.equals(fsClass)) {
			fsClassName = "Indexed Filesystem (V1)";
		}
		else if (IndexedLocalFileSystem.class.equals(fsClass)) {
			fsClassName = "Indexed Filesystem (V0)";
		}
		else if (MangledLocalFileSystem.class.equals(fsClass)) {
			fsClassName = "Mangled Filesystem";
		}

		JLabel label = new GLabel(fsClassName);
		label.setName("Project Storage Type");
		infoPanel.add(label);
		infoPanel.add(new GLabel("Project Name:", SwingConstants.RIGHT));
		label = new GLabel(project.getName());
		label.setName("Project Name");
		infoPanel.add(label);

		outerPanel.add(infoPanel);
		return outerPanel;
	}

	private JPanel buildButtonPanel() {
		JPanel buttonPanel = new JPanel(new BorderLayout());

		changeConvertButton = new JButton(repository != null ? CHANGE : CONVERT);
		changeConvertButton.addActionListener(e -> {
			if (changeConvertButton.getText().equals(CONVERT)) {
				convertToShared();
			}
			else {
				updateSharedProjectInfo();
			}
		});

		HelpService help = Help.getHelpService();
		String tag = repository != null ? "Change_Shared_Project_Info" : "Convert_to_Shared";
		help.registerHelp(changeConvertButton, new HelpLocation(GenericHelpTopics.FRONT_END, tag));

		String toolTipForChange = "Change server information or specify another repository.";
		String toolTipForConvert = "Convert project to be a shared project.";
		changeConvertButton.setToolTipText(
			repository != null ? toolTipForChange : toolTipForConvert);

		Class<? extends LocalFileSystem> fsClass = project.getProjectData().getLocalStorageClass();
		String convertStorageButtonLabel = null;
		if (IndexedLocalFileSystem.class.equals(fsClass)) {
			convertStorageButtonLabel = "Upgrade Project Storage Index...";
		}
		else if (MangledLocalFileSystem.class.equals(fsClass)) {
			convertStorageButtonLabel = "Convert Project Storage to Indexed...";
		}

		if (convertStorageButtonLabel != null) {
			convertStorageButton = new JButton(convertStorageButtonLabel);
			convertStorageButton.addActionListener(e -> convertToIndexedFilesystem());
			help.registerHelp(changeConvertButton,
				new HelpLocation(GenericHelpTopics.FRONT_END, "Convert_Project_Storage"));
			convertStorageButton.setToolTipText(
				"Convert/Upgrade project storage to latest Indexed Filesystem");
		}

		JPanel p = new JPanel(new FlowLayout());
		p.add(changeConvertButton);
		if (convertStorageButton != null) {
			p.add(convertStorageButton);
		}
		buttonPanel.add(p);

		return buttonPanel;
	}

	private JPanel buildRepositoryInfoPanel() {

		String serverName = "";
		ServerInfo info = null;
		String repositoryName = "";
		String portNumberStr = "";
		boolean isConnected = false;
		if (repository != null) {
			info = repository.getServerInfo();
			serverName = info.getServerName();
			repositoryName = repository.getName();
			portNumberStr = Integer.toString(info.getPortNumber());
			isConnected = repository.isConnected();
		}

		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.setBorder(BorderFactory.createTitledBorder("Repository Info"));

		JPanel panel = new JPanel(new PairLayout(5, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

		JLabel sLabel = new GDLabel("Server Name:", SwingConstants.RIGHT);
		panel.add(sLabel);
		serverLabel = new GDLabel(serverName);
		serverLabel.setName("Server Name");
		panel.add(serverLabel);

		JLabel pLabel = new GDLabel("Port Number:", SwingConstants.RIGHT);
		panel.add(pLabel);
		portLabel = new GDLabel(portNumberStr);
		portLabel.setName("Port Number");
		panel.add(portLabel);

		JLabel repLabel = new GDLabel("Repository Name:", SwingConstants.RIGHT);
		panel.add(repLabel);
		repNameLabel = new GDLabel(repositoryName);
		repNameLabel.setName("Repository Name");
		panel.add(repNameLabel);

		JLabel connectLabel = new GDLabel("Connection Status:", SwingConstants.RIGHT);
		panel.add(connectLabel);

		connectionButton = new JButton(
			isConnected ? FrontEndPlugin.CONNECTED_ICON : FrontEndPlugin.DISCONNECTED_ICON);
		connectionButton.addActionListener(e -> connect());
		connectionButton.setName("Connect Button");
		connectionButton.setContentAreaFilled(false);
		connectionButton.setSelected(isConnected);
		connectionButton.setBorder(
			isConnected ? BorderFactory.createBevelBorder(BevelBorder.LOWERED)
					: BorderFactory.createBevelBorder(BevelBorder.RAISED));
		updateConnectButtonToolTip();
		HelpService help = Help.getHelpService();
		help.registerHelp(connectionButton,
			new HelpLocation(GenericHelpTopics.FRONT_END, "ConnectToServer"));

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder());
		buttonPanel.add(connectionButton);
		panel.add(buttonPanel);

		JLabel userLabel = new GDLabel("User Access Level:", SwingConstants.RIGHT);
		userLabel.setToolTipText("Indicates your privileges in the shared repository");
		panel.add(userLabel);
		User user = null;
		if (isConnected) {
			try {
				user = repository.getUser();
			}
			catch (IOException e) {
				Msg.error(this, "Unable to get the current user", e);
			}
		}
		userAccessLabel = new GDLabel(getAccessString(user));
		userAccessLabel.setName("User Access Level");
		panel.add(userLabel);
		panel.add(userAccessLabel);

		outerPanel.add(panel);

		if (repository == null) {
			sLabel.setEnabled(false);
			pLabel.setEnabled(false);
			repLabel.setEnabled(false);
			connectLabel.setEnabled(false);
			connectionButton.setEnabled(false);
			userLabel.setEnabled(false);
		}
		return outerPanel;
	}

	private void updateConnectButtonToolTip() {

		if (repository != null) {
			ServerInfo info = repository.getServerInfo();
			String serverName = info.getServerName();
			String notConnectedToolTip = HTMLUtilities.toHTML(
				"Disconnected from " + serverName + ".\n" + "Activate this button to connect.");
			connectionButton.setToolTipText(
				repository.isConnected() ? "Connected to " + serverName : notConnectedToolTip);
		}
	}

	private void connect() {
		try {
			repository.connect();
		}
		catch (NotConnectedException e) {
			// message displayed by repository server adapter
		}
		catch (IOException e) {
			ClientUtil.handleException(repository, e, "Repository Connection", rootPanel);
		}
	}

	private String getAccessString(User user) {
		if (user == null) {
			return "";
		}
		if (user.isAdmin()) {
			return "Administrator";
		}
		if (user.isReadOnly()) {
			return "Read Only";
		}
		return "Read/Write";
	}

	private void updateSharedProjectInfo() {
		if (filesAreOpen()) {
			Msg.showInfo(getClass(), getComponent(), "Cannot Change Project Info with Open Files",
				"Before your project info can be updated, you must close\n" +
					"files in running tools and make sure you have no files\n" + "checked out.");
			return;
		}

		SetupProjectPanelManager panelManager =
			new SetupProjectPanelManager(plugin.getTool(), project.getRepository().getServerInfo());
		WizardManager wm = new WizardManager("Change Shared Project Information", true,
			panelManager, CONVERT_ICON);
		wm.showWizard(getComponent());
		RepositoryAdapter rep = panelManager.getProjectRepository();
		if (rep != null) {
			RepositoryAdapter currentRepository = project.getRepository();
			if (currentRepository.getServerInfo().equals(rep.getServerInfo()) &&
				currentRepository.getName().equals(rep.getName())) {
				Msg.showInfo(getClass(), getComponent(), "No Changes Made",
					"No changes were made to the shared project information.");
			}
			else if (OptionDialog.showOptionDialog(getComponent(), "Update Shared Project Info",
				"Are you sure you want to update your shared project information?", "Update",
				OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {

				UpdateInfoTask task = new UpdateInfoTask(rep);
				new TaskLauncher(task, getComponent(), 500);
				// block until task completes
				if (task.getStatus()) {
					FileActionManager actionMgr = plugin.getFileActionManager();
					close();
					actionMgr.closeProject(false);
					actionMgr.openProject(project.getProjectLocator());
					plugin.getProjectActionManager().showProjectInfo();
				}
			}
		}

	}

	private void convertToIndexedFilesystem() {
		if (filesAreOpen()) {
			Msg.showInfo(getClass(), getComponent(),
				"Cannot Convert/Upgrade Project Storage with Open Files",
				"Before your project can be converted, you must close\n" +
					"files in running tools.");
			return;
		}

		RepositoryAdapter rep = project.getRepository();
		if (rep != null) {
			rep.disconnect();
		}

		if (OptionDialog.showOptionDialog(getComponent(), "Confirm Convert/Upgrade Project Storage",
			"Convert/Upgrade Project Storage to latest Indexed Filesystem ?\n \n" +
				"WARNING!  Once converted a project may no longer be opened by\n" +
				"any version of Ghidra older than version 6.1.",
			"Convert", OptionDialog.WARNING_MESSAGE) == OptionDialog.OPTION_ONE) {

			ProjectLocator projectLocator = project.getProjectLocator();
			FileActionManager actionMgr = plugin.getFileActionManager();
			actionMgr.closeProject(false);

			// put the conversion in a task
			ConvertProjectStorageTask task = new ConvertProjectStorageTask(projectLocator);
			new TaskLauncher(task, getComponent(), 500);

			// block until task completes
			if (task.getStatus()) {
				close();
				actionMgr.openProject(projectLocator);
				plugin.getProjectActionManager().showProjectInfo();
			}
		}

	}

	private void convertToShared() {
		if (filesAreOpen()) {
			Msg.showInfo(getClass(), getComponent(), "Cannot Convert Project with Open Files",
				"Before your project can be converted, you must close\n" +
					"files in running tools and make sure you have no files\n" + "checked out.");
			return;
		}

		SetupProjectPanelManager panelManager =
			new SetupProjectPanelManager(plugin.getTool(), null);
		WizardManager wm = new WizardManager("Convert Project", true, panelManager, CONVERT_ICON);
		wm.showWizard(getComponent());
		RepositoryAdapter rep = panelManager.getProjectRepository();
		if (rep != null) {
			StringBuffer confirmMsg = new StringBuffer();
			confirmMsg.append("All version history on your files will be\n" +
				"lost after your project is converted.\n" +
				"Do you want to convert your project?\n");
			confirmMsg.append(" \n");
			confirmMsg.append("WARNING: Convert CANNOT be undone!");

			if (OptionDialog.showOptionDialog(getComponent(), "Confirm Convert Project",
				confirmMsg.toString(), "Convert",
				OptionDialog.WARNING_MESSAGE) == OptionDialog.OPTION_ONE) {
				// put the conversion in a task
				ConvertProjectTask task = new ConvertProjectTask(rep);
				new TaskLauncher(task, getComponent(), 500);
				// block until task completes
				if (task.getStatus()) {
					close();
					FileActionManager actionMgr = plugin.getFileActionManager();
					actionMgr.closeProject(false);
					actionMgr.openProject(project.getProjectLocator());
					plugin.getProjectActionManager().showProjectInfo();
				}
				else {
					Msg.trace(this, "Convert project task failed");
				}
			}
		}
	}

	private boolean filesAreOpen() {
		PluginTool[] tools = project.getToolManager().getRunningTools();

		if (tools.length > 0) {
			for (PluginTool tool : tools) {
				if (tool.getDomainFiles().length > 0) {
					return true;
				}
			}
		}

		return false;
	}

	private class ConvertProjectTask extends Task {
		private RepositoryAdapter taskRepository;
		private boolean status;

		ConvertProjectTask(RepositoryAdapter repository) {
			super("Convert Project to Shared", true, false, true);
			this.taskRepository = repository;
		}

		/* (non-Javadoc)
		 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			try {
				project.getProjectData().convertProjectToShared(taskRepository, monitor);
				status = true;
			}
			catch (IOException e) {
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				Msg.showError(this, getComponent(), "Failed to Convert Project",
					"Update to shared project info failed:\n" + msg);
			}
			catch (CancelledException e) {
				Msg.info(this, "Update shared project info was canceled.");
			}
		}

		boolean getStatus() {
			return status;
		}
	}

	private class ConvertProjectStorageTask extends Task {
		private ProjectLocator projectLocator;
		private boolean status;

		ConvertProjectStorageTask(ProjectLocator projectLocator) {
			super("Convert Project Storage", false, false, true);
			this.projectLocator = projectLocator;
		}

		/* (non-Javadoc)
		 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			try {
				monitor.setMessage("Converting storage...");
				File projectDir = projectLocator.getProjectDir();
				ConvertFileSystem.convertProject(projectDir,
					new ConvertFileSystem.MessageListener() {
						@Override
						public void println(String string) {
							Msg.info(this, string);
						}
					});
				status = true;
			}
			catch (ConvertFileSystem.ConvertFileSystemException e) {
				Msg.showError(this, getComponent(), "Failed to Convert Project Storage",
					e.getMessage());
			}
		}

		boolean getStatus() {
			return status;
		}
	}

	private class UpdateInfoTask extends Task {
		private RepositoryAdapter taskRepository;
		private boolean status;

		UpdateInfoTask(RepositoryAdapter repository) {
			super("Update Shared Project Info", true, false, true);
			this.taskRepository = repository;
		}

		/* (non-Javadoc)
		 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			try {
				// NOTE: conversion of non-shared project will lose version history
				project.getProjectData().updateRepositoryInfo(taskRepository, monitor);
				status = true;
			}
			catch (IOException e) {
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				Msg.showError(this, getComponent(), "Failed to Update Shared Project Info",
					"Conversion to shared project failed:\n" + msg);
			}
			catch (CancelledException e) {
				Msg.info(this, "Convert project was canceled.");
			}
		}

		boolean getStatus() {
			return status;
		}
	}

}
