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

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;

import docking.StatusBarSpacer;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.task.BufferedSwingRunner;
import log.LogListener;
import log.LogPanelAppender;
import resources.ResourceManager;

/**
 * A JPanel that contains a label to show the last message displayed. It also has a button to 
 * show the Console. 
 */
public class LogPanel extends JPanel implements LogListener {

	private JButton button;
	private JLabel label;
	private Color defaultColor;

	private BufferedSwingRunner messageUpdater = new BufferedSwingRunner();

	LogPanel(final FrontEndPlugin plugin) {
		super(new BorderLayout());
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(8, 4, 4, 2));
		button = new EmptyBorderButton(ResourceManager.loadImage("images/monitor.png"));
		label = new GDLabel();
		label.setName("Details");
		defaultColor = label.getForeground();
		panel.add(label, BorderLayout.CENTER);

		JPanel eastPanel = new JPanel(new HorizontalLayout(0));
		eastPanel.add(button);
		eastPanel.add(new StatusBarSpacer());
		panel.add(eastPanel, BorderLayout.EAST);

		Border b = BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5),
			BorderFactory.createLoweredBevelBorder());
		label.setBorder(b);

		button.setPreferredSize(new Dimension(24, 24));
		button.setFocusable(false);
		button.setToolTipText("Show Console (Refresh Open Console)");
		button.addActionListener(e -> {
			FrontEndTool tool = (FrontEndTool) plugin.getTool();
			tool.showGhidraUserLogFile();
		});

		addLogAppender();
		add(panel, BorderLayout.NORTH);
	}

	/**
	 * Set the help location for the components in the LogPanel.
	 * @param helpLocation help location for this LogPanel
	 * 
	 */
	public void setHelpLocation(HelpLocation helpLocation) {
		HelpService help = Help.getHelpService();
		help.registerHelp(button, helpLocation);
		button.setFocusable(true);
	}

	@Override
	public void messageLogged(String message, boolean isError) {

		messageUpdater.run(() -> {
			label.setForeground(isError ? Color.RED : defaultColor);
			String text = message.replace("\n", " ");
			label.setText(text);
			label.setToolTipText(text);
		});
	}

	/**
	 * Extracts the {@link LogPanelAppender} from the root logger configuration
	 * and hands an instance of this panel to it. 
	 */
	private void addLogAppender() {
		LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
		Configuration config = ctx.getConfiguration();
		LogPanelAppender logAppender = config.getAppender("logPanel");
		if (logAppender == null) {
			Msg.error(this, "Couldn't find LogPanelAppender instance in the Log4j context; " +
				"nothing will be logged to the application's Front-end panel.");
			return;
		}

		logAppender.setLogListener(this);
	}

}
