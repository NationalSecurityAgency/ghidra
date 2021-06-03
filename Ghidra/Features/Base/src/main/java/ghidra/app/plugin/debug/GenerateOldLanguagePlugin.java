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
package ghidra.app.plugin.debug;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.*;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.XMLOutputter;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.bean.SelectLanguagePanel;
import ghidra.framework.Application;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.xml.GenericXMLOutputter;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Generate Old Language File",
	description = "This plugin allows the user to generate an old-language XML " +
			"file from the current version of a loaded language.  " +
			"This should be done prior to making any changes to a " +
			"language which will modify its address spaces or register definitions."
)
//@formatter:on
public class GenerateOldLanguagePlugin extends Plugin implements FrontEndable {

	private static final ExtensionFileFilter OLD_LANG_FILTER = new ExtensionFileFilter("lang",
		"Old Language File");
	private static final ExtensionFileFilter TRANSLATOR_FILTER = new ExtensionFileFilter("trans",
		"Simple Translator File");

	private DockingAction generateOldLanguageAction;
	private DockingAction generateTranslatorAction;

	public GenerateOldLanguagePlugin(PluginTool plugintool) {
		super(plugintool);
	}

	@Override
	protected void init() {

		generateOldLanguageAction = new DockingAction("Generate Old Language File", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				GenerateOldLanguageDialog dialogProvider = new GenerateOldLanguageDialog(false);
				tool.showDialog(dialogProvider);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}
		};
// ACTIONS - auto generated
		generateOldLanguageAction.setMenuBarData(new MenuData(new String[] { "File",
			"Generate Old Language File..." }, null, "Language"));

		generateOldLanguageAction.setEnabled(true);
		tool.addAction(generateOldLanguageAction);

		generateTranslatorAction =
			new DockingAction("Generate Simple Language Translator", getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					GenerateOldLanguageDialog dialogProvider = new GenerateOldLanguageDialog(true);
					tool.showDialog(dialogProvider);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return true;
				}
			};
// ACTIONS - auto generated
		generateTranslatorAction.setMenuBarData(new MenuData(new String[] { "File",
			"Generate Simple Language Translator..." }, null, "Language"));

		generateTranslatorAction.setEnabled(true);
		tool.addAction(generateTranslatorAction);
	}

	@Override
	protected void dispose() {
		tool.removeAction(generateOldLanguageAction);
		tool.removeAction(generateTranslatorAction);
		super.dispose();
	}

	private class GenerateOldLanguageDialog extends DialogComponentProvider {

		private JPanel panel;
		private SelectLanguagePanel selectLangPanel;
		private GhidraFileChooser chooser;

		GenerateOldLanguageDialog(final boolean skipOldLangGeneration) {
			super("Select Old Language", true, true, true, false);

			selectLangPanel =
				new SelectLanguagePanel(new DeprecatedLanguageService(skipOldLangGeneration));
			selectLangPanel.setPreferredSize(new Dimension(450, 150));
			selectLangPanel.setShowVersion(true);

			panel = new JPanel(new BorderLayout());
			panel.setBorder(new EmptyBorder(10, 10, 10, 10));
			panel.add(selectLangPanel, BorderLayout.CENTER);
			addWorkPanel(panel);

			setStatusText("Please select old language");

			JButton genButton = new JButton(skipOldLangGeneration ? "Select" : "Generate...");
			genButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					Language lang = selectLangPanel.getSelectedLanguage();
					if (lang == null) {
						setStatusText("Please select old language");
						return;
					}
					if (skipOldLangGeneration) {
						// All we need is old language for translator generation
						close();
						GenerateTranslatorDialog translatorDlgProvider =
							new GenerateTranslatorDialog(lang, null);
						GenerateOldLanguagePlugin.this.tool.showDialog(translatorDlgProvider);
						return;
					}

					if (chooser == null) {
						chooser = new GhidraFileChooser(panel);
						chooser.setTitle("Specify Old Language Output File");
						chooser.setFileFilter(OLD_LANG_FILTER);
						chooser.setApproveButtonText("Create");
						// there's no single directory; you need to pick it yourself now
//						chooser.setCurrentDirectory(LANGUAGE_DIR);
						chooser.setCurrentDirectory(Application.getApplicationRootDirectory().getFile(
							false));
					}
					File file = chooser.getSelectedFile(true);
					if (file == null) {
						return;
					}
					if (!file.getName().endsWith(OldLanguageFactory.OLD_LANGUAGE_FILE_EXT)) {
						file =
							new File(file.getParent(), file.getName() +
								OldLanguageFactory.OLD_LANGUAGE_FILE_EXT);
					}
					if (file.exists()) {
						if (OptionDialog.showYesNoDialog(panel, "Confirm Overwrite",
							"Overwrite file " + file.getName() + "?") != OptionDialog.YES_OPTION) {
							return;
						}
					}

					try {
						OldLanguageFactory.createOldLanguageFile(lang, file);
						close();

						int resp =
							OptionDialog.showYesNoDialog(
								GenerateOldLanguagePlugin.this.tool.getToolFrame(),
								"Create Simple Translator?",
								"Old language file generated successfully.\n \n"
									+ "Would you like to create a simple translator to another language?");
						if (resp == OptionDialog.YES_OPTION) {
							GenerateTranslatorDialog translatorDlgProvider =
								new GenerateTranslatorDialog(lang, file);
							GenerateOldLanguagePlugin.this.tool.showDialog(translatorDlgProvider);
						}
					}
					catch (LanguageNotFoundException e) {
						throw new AssertException(e);
					}
					catch (IOException e) {
						Msg.showError(this, panel, "IO Error",
							"Error occurred while generating old language file:\n" + file, e);
					}
				}
			});
			addButton(genButton);

			addCancelButton();
		}

		@Override
		public void close() {
			super.close();
			selectLangPanel.dispose();
		}
	}

	private class GenerateTranslatorDialog extends DialogComponentProvider {

		private JPanel panel;
		private SelectLanguagePanel selectLangPanel;
		private GhidraFileChooser chooser;

		private Language oldLang;
		private File oldLangFile;

		GenerateTranslatorDialog(Language oldLang, File oldLangFile) {
			super("Select New Language", true, true, true, false);
			this.oldLang = oldLang;
			this.oldLangFile = oldLangFile;

			selectLangPanel = new SelectLanguagePanel(DefaultLanguageService.getLanguageService());
			selectLangPanel.setPreferredSize(new Dimension(450, 150));
			selectLangPanel.setShowVersion(true);

			// TODO: add translator options

			panel = new JPanel(new BorderLayout());
			panel.setBorder(new EmptyBorder(10, 10, 10, 10));
			panel.add(selectLangPanel, BorderLayout.CENTER);
			addWorkPanel(panel);

			setStatusText("Please select target language");

			JButton genButton = new JButton("Generate...");
			genButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent evt) {
					Language lang = selectLangPanel.getSelectedLanguage();
					if (lang == null) {
						setStatusText("Please select target language");
						return;
					}

					File transFile;
					if (GenerateTranslatorDialog.this.oldLangFile == null) {
						if (chooser == null) {
							chooser = new GhidraFileChooser(panel);
							chooser.setTitle("Specify Old Language Output File");
							chooser.setFileFilter(TRANSLATOR_FILTER);
							chooser.setApproveButtonText("Create");
							// there's no single directory; you need to pick it yourself now
//							chooser.setCurrentDirectory(LANGUAGE_DIR);
							chooser.setCurrentDirectory(Application.getApplicationRootDirectory().getFile(
								false));
						}
						transFile = chooser.getSelectedFile(true);
						if (transFile == null) {
							return;
						}
						if (!transFile.getName().endsWith(
							LanguageTranslatorFactory.LANGUAGE_TRANSLATOR_FILE_EXT)) {
							transFile =
								new File(transFile.getParent(), transFile.getName() +
									LanguageTranslatorFactory.LANGUAGE_TRANSLATOR_FILE_EXT);
						}
					}
					else {
						String filename = GenerateTranslatorDialog.this.oldLangFile.getName();
						int index = filename.indexOf(OldLanguageFactory.OLD_LANGUAGE_FILE_EXT);
						if (index > 0) {
							filename =
								filename.substring(0, index) +
									LanguageTranslatorFactory.LANGUAGE_TRANSLATOR_FILE_EXT;
						}
						transFile =
							new File(GenerateTranslatorDialog.this.oldLangFile.getParentFile(),
								filename);
					}
					if (transFile.exists()) {
						if (OptionDialog.showYesNoDialog(panel, "Confirm Overwrite",
							"Overwrite file " + transFile.getName() + "?") != OptionDialog.YES_OPTION) {
							return;
						}
					}
					try {

						buildDefaultTranslator(lang, transFile);

					}
					catch (IOException e) {
						Msg.showError(this, panel, "IO Error",
							"Error occurred while generating translator file:\n" + transFile, e);
					}
					close();
				}

			});
			addButton(genButton);

			addCancelButton();
		}

		@Override
		public void close() {
			super.close();
			selectLangPanel.dispose();
		}

		private void buildDefaultTranslator(Language newLang, File transFile) throws IOException {

			DummyLanguageTranslator defaultTrans = new DummyLanguageTranslator(oldLang, newLang);
			if (!defaultTrans.isValid()) {
				throw new AssertException();
			}

			Element root = new Element("language_translation");

			Element fromLang = new Element("from_language");
			fromLang.setAttribute("version", Integer.toString(oldLang.getVersion()));
			fromLang.setText(oldLang.getLanguageID().getIdAsString());
			root.addContent(fromLang);

			Element toLang = new Element("to_language");
			toLang.setAttribute("version", Integer.toString(newLang.getVersion()));
			toLang.setText(newLang.getLanguageID().getIdAsString());
			root.addContent(toLang);

			for (CompilerSpecDescription oldCompilerSpecDescription : oldLang.getCompatibleCompilerSpecDescriptions()) {
				CompilerSpecID oldCompilerSpecID = oldCompilerSpecDescription.getCompilerSpecID();
				String newId;
				try {
					newId =
						newLang.getCompilerSpecByID(oldCompilerSpecID).getCompilerSpecID().getIdAsString();
				}
				catch (CompilerSpecNotFoundException e) {
					newId = newLang.getDefaultCompilerSpec().getCompilerSpecID().getIdAsString();
				}
				Element compilerSpecMapElement = new Element("map_compiler_spec");
				compilerSpecMapElement.setAttribute("from", oldCompilerSpecID.getIdAsString());
				compilerSpecMapElement.setAttribute("to", newId);
				root.addContent(compilerSpecMapElement);
			}

			if (!defaultTrans.canMapSpaces) {
				for (AddressSpace space : oldLang.getAddressFactory().getPhysicalSpaces()) {
					Element mapSpaceElement = new Element("map_space");
					mapSpaceElement.setAttribute("from", space.getName());
					mapSpaceElement.setAttribute("to", "?" + space.getSize());
					root.addContent(mapSpaceElement);
				}
			}

			for (Register reg : oldLang.getRegisters()) {
				Register newReg = defaultTrans.getNewRegister(reg);
				if (newReg == null) {
					Element mapRegElement = new Element("map_register");
					mapRegElement.setAttribute("from", reg.getName());
					mapRegElement.setAttribute("to", ("?" + reg.getMinimumByteSize()));
					mapRegElement.setAttribute("size", Integer.toString(reg.getMinimumByteSize()));
					root.addContent(mapRegElement);
				}
			}

			Document doc = new Document(root);
			FileOutputStream out = new FileOutputStream(transFile);
			XMLOutputter xml = new GenericXMLOutputter();
			xml.output(doc, out);
			out.close();

			Register oldCtx = oldLang.getContextBaseRegister();
			Register newCtx = newLang.getContextBaseRegister();
			boolean contextWarning = false;
			if (oldCtx != null && defaultTrans.isValueTranslationRequired(oldCtx)) {
				contextWarning = true;
			}
			else if (oldCtx == null && newCtx != null) {
				contextWarning = true;
			}
			if (contextWarning) {
				Msg.showWarn(getClass(), tool.getToolFrame(), "Translator Warning",
					"The new context register differs from the old context!\n"
						+ "A set_context element or custom translator may be required.");
			}
		}
	}

	private static class DummyLanguageTranslator extends LanguageTranslatorAdapter {

		private boolean canMapSpaces;
		private boolean canMapContext;

		DummyLanguageTranslator(Language oldLanguage, Language newLanguage) {
			super(oldLanguage.getLanguageID(), oldLanguage.getVersion(),
				newLanguage.getLanguageID(), newLanguage.getVersion());
		}

		@Override
		public boolean isValid() {
			if (super.isValid()) {
				try {
					validateDefaultSpaceMap();
					canMapSpaces = true;
				}
				catch (IncompatibleLanguageException e) {
					canMapSpaces = false;
					Msg.error(this, e.getMessage());
				}
// Leave proper mapping up to the language writer
//				try {
//					validateContextRegisterMapping();
//					canMapContext = true;
//				} catch (IncompatibleLanguageException e) {
//					canMapContext = false;
//					Err.error(this, e.getMessage());
//				}
				return true;
			}
			return false;
		}

		boolean canMapSpaces() {
			return canMapSpaces;
		}

		boolean canMapContext() {
			return canMapContext;
		}
	}

	/**
	 * Language service which includes all languages, including old and deprecated
	 */
	private static class DeprecatedLanguageService implements VersionedLanguageService {

		LanguageService langService = DefaultLanguageService.getLanguageService();
		OldLanguageFactory oldLangFactory = OldLanguageFactory.getOldLanguageFactory();
		private final boolean includeOldLanguages;

		DeprecatedLanguageService(boolean includeOldLanguages) {
			this.includeOldLanguages = includeOldLanguages;
		}

		@Override
		public Language getDefaultLanguage(Processor processor) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Language getLanguage(LanguageID languageID) throws LanguageNotFoundException {
			try {
				return langService.getLanguage(languageID);
			}
			catch (LanguageNotFoundException e) {
				LanguageDescription langDescr = oldLangFactory.getLatestOldLanguage(languageID);
				if (langDescr != null) {
					return oldLangFactory.getOldLanguage(languageID, langDescr.getVersion());
				}
				throw e;
			}
		}

		@Override
		public Language getLanguage(LanguageID languageID, int version)
				throws LanguageNotFoundException {
			Language language = oldLangFactory.getOldLanguage(languageID, version);
			if (language == null) {
				language = langService.getLanguage(languageID);
				if (language != null && language.getLanguageDescription().getVersion() != version) {
					throw new LanguageNotFoundException(languageID, "version: " + version);
				}
			}
			return language;
		}

		@Override
		public LanguageDescription getLanguageDescription(LanguageID languageID)
				throws LanguageNotFoundException {
			try {
				return langService.getLanguageDescription(languageID);
			}
			catch (LanguageNotFoundException e) {
				LanguageDescription langDescr = oldLangFactory.getLatestOldLanguage(languageID);
				if (langDescr != null) {
					return langDescr;
				}
				throw e;
			}
		}

		@Override
		public LanguageDescription getLanguageDescription(LanguageID languageID, int version)
				throws LanguageNotFoundException {
			Language language = oldLangFactory.getOldLanguage(languageID, version);
			if (language != null) {
				return language.getLanguageDescription();
			}
			LanguageDescription languageDescription =
				langService.getLanguageDescription(languageID);
			if (languageDescription.getVersion() != version) {
				throw new LanguageNotFoundException(languageID, "version: " + version);
			}
			return languageDescription;
		}

		@Override
		public List<LanguageDescription> getLanguageDescriptions(boolean includeDeprecatedLanguages) {
			// Include deprecated languages
			List<LanguageDescription> list = new ArrayList<LanguageDescription>();
			list.addAll(langService.getLanguageDescriptions(true));
			if (includeOldLanguages) {
				list.addAll(Arrays.asList(oldLangFactory.getLatestOldLanaguageDescriptions()));
			}
			return list;
		}

		/**
		 * @see ghidra.program.model.lang.LanguageService#getLanguageDescriptions(ghidra.program.model.lang.Processor, ghidra.program.model.lang.Endian, java.lang.Integer, java.lang.String)
		 */
		@Override
		public List<LanguageDescription> getLanguageDescriptions(Processor processor,
				Endian endianess, Integer size, String variant) {
			throw new UnsupportedOperationException();
		}

		/**
		 * @see ghidra.program.model.lang.LanguageService#getLanguageDescriptions(ghidra.program.model.lang.Processor)
		 */
		@Override
		public List<LanguageDescription> getLanguageDescriptions(Processor processorName) {
			throw new UnsupportedOperationException();
		}

		@Override
		public List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(
				LanguageCompilerSpecQuery query) {
			throw new UnsupportedOperationException();
		}

		@Override
		public List<LanguageCompilerSpecPair> getLanguageCompilerSpecPairs(
				ExternalLanguageCompilerSpecQuery query) {
			throw new UnsupportedOperationException();
		}
	}
}
