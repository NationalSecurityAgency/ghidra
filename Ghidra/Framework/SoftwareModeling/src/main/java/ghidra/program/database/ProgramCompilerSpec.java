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
package ghidra.program.database;

import java.beans.PropertyEditor;
import java.util.*;

import docking.options.editor.StringWithChoicesEditor;
import generic.stl.Pair;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * A Program specific version of the CompilerSpec.
 * 
 * Every Program owns a specific ProgramCompilerSpec.  It is based on a CompilerSpec
 * returned by the Language assigned to the Program, but it may include extensions.
 * Extensions are currently either a new form of:
 *    - PrototypeModel or
 *    - InjectPayload
 * 
 * Extensions can be installed or removed from a ProgramDB via the Options mechanism (See SpecExtension)
 * using SpecExtension.addReplaceCompilerSpecExtension() or SpecExtension.removeCompilerSpecExtension().
 * 
 * ProgramCompilerSpec allows the static evaluation models, described by the underlying BasicCompilerSpec
 * and returned by getPrototypeEvaluationModel(), to be overridden by Program specific options.
 * 
 * getDecompilerOutputLanguage() queries the Program specific language the decompiler should use as output.
 * 
 * installExtensions() is the main entry point for integrating the Program Options
 * with the Language's base CompilerSpec and producing a complete in-memory CompilerSpec for the Program.
 * 
 */
public class ProgramCompilerSpec extends BasicCompilerSpec {

	public static final String DECOMPILER_PROPERTY_LIST_NAME = "Decompiler";
	public static final String DECOMPILER_OUTPUT_LANGUAGE = "Output Language";
	public final static DecompilerLanguage DECOMPILER_OUTPUT_DEF = DecompilerLanguage.C_LANGUAGE;
	public final static String DECOMPILER_OUTPUT_DESC =
		"Select the source language output by the decompiler.";

	public static final String EVALUATION_MODEL_PROPERTY_NAME = "Prototype Evaluation";

	private Program program;						// Program owning this compiler spec
	private Map<String, PrototypeModel> usermodels = null;
	private int versionCounter = 0;					// Version number among all cspec variants for the same Program

	/**
	 * Construct the CompilerSpec for a Program based on a Language CompilerSpec
	 * @param program is the Program
	 * @param langSpec is the CompilerSpec from Language to base this on
	 */
	private ProgramCompilerSpec(Program program, BasicCompilerSpec langSpec) {
		super(langSpec);
		this.program = program;
	}

	/**
	 * Adds and enables an option to have the decompiler display java.
	 * @param program to be enabled
	 */
	public static void enableJavaLanguageDecompilation(Program program) {
		Options decompilerPropertyList = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		decompilerPropertyList.registerOption(DECOMPILER_OUTPUT_LANGUAGE, DECOMPILER_OUTPUT_DEF,
			null, DECOMPILER_OUTPUT_DESC);
		decompilerPropertyList.setEnum(DECOMPILER_OUTPUT_LANGUAGE,
			DecompilerLanguage.JAVA_LANGUAGE);
	}

	@Override
	public DecompilerLanguage getDecompilerOutputLanguage() {
		Options options = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		if (options.contains(DECOMPILER_OUTPUT_LANGUAGE)) {
			return options.getEnum(DECOMPILER_OUTPUT_LANGUAGE, DECOMPILER_OUTPUT_DEF);
		}
		return DECOMPILER_OUTPUT_DEF;
	}

	/**
	 * Install a new set of user-defined (extension) prototype models.
	 * All the models from the compiler spec are preserved. Any old user-defined
	 * models are removed or replaced.
	 * @param extensions is the list of new user-defined models
	 */
	private void installPrototypeExtensions(List<PrototypeModel> extensions) {
		if (usermodels == null) {
			if (extensions.isEmpty()) {
				return;		// No change to prototypes
			}
			usermodels = new TreeMap<>();
		}
		ArrayList<PrototypeModel> finalList = new ArrayList<>();
		TreeSet<String> currentNames = new TreeSet<>();
		for (PrototypeModel model : allmodels) {
			currentNames.add(model.getName());
			if (usermodels.containsKey(model.getName())) {
				continue;
			}
			finalList.add(model);		// Add original non-userdef models
		}

		for (PrototypeModel model : extensions) {
			if (currentNames.contains(model.getName())) {
				if (!usermodels.containsKey(model.getName())) {
					Msg.warn(this,
						"Cannot override prototype model " + model.getName() + " with extension");
					continue;
				}
			}
			markPrototypeAsExtension(model);
			finalList.add(model);
			usermodels.put(model.getName(), model);
		}
		String defaultName = null;
		String evalName = null;
		String evalCalledName = null;
		if (defaultModel != null) {
			defaultName = defaultModel.getName();
		}
		if (evalCurrentModel != null) {
			evalName = evalCurrentModel.getName();
		}
		if (evalCalledModel != null) {
			evalCalledName = evalCalledModel.getName();
		}
		modelXrefs(finalList, defaultName, evalName, evalCalledName);
		if (usermodels.isEmpty()) {
			usermodels = null;
		}
	}

	/**
	 * Add a new PrototypeModel to the list of extensions with errors
	 * @param errList is the list of errors
	 * @param model is the PrototypeModel with errors
	 * @return the updated list
	 */
	private static ArrayList<String> addPrototypeError(ArrayList<String> errList,
			PrototypeModel model) {
		if (model.isErrorPlaceholder()) {
			if (errList == null) {
				errList = new ArrayList<>();
			}
			else if (errList.size() > 4) {		// Only accumulate up to 5
				errList.add("...");
				return errList;
			}
			String message = "prototype: " + model.getName();
			errList.add(message);
		}
		return errList;
	}

	/**
	 * Add a new InjectPayload to the list of extensions with errors
	 * @param errList is the list of errors
	 * @param payload is the InjectPayload with errors
	 * @return the updated list
	 */
	private static ArrayList<String> addPayloadError(ArrayList<String> errList,
			InjectPayload payload) {
		if (payload.isErrorPlaceholder()) {
			if (errList == null) {
				errList = new ArrayList<>();
			}
			else if (errList.size() > 4) {		// Only accumulate up to 5
				errList.add("...");
				return errList;
			}
			String message;
			if (payload instanceof InjectPayloadCallfixup) {
				message = "callfixup: " + payload.getName();
			}
			else {
				message = "callotherfixup: " + payload.getName();
			}
			errList.add(message);
		}
		return errList;
	}

	/**
	 * Update the choices presented for evaluation model program option.
	 */
	private void updateModelChoices() {
		Options decompilerPropertyList = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		PropertyEditor editor =
			decompilerPropertyList.getRegisteredPropertyEditor(EVALUATION_MODEL_PROPERTY_NAME);
		if (editor == null) {
			return;
		}
		if (!(editor instanceof StringWithChoicesEditor)) {
			return;
		}
		String[] evalChoices = establishEvaluationModelChoices(evalCurrentModel);
		StringWithChoicesEditor choiceEditor = (StringWithChoicesEditor) editor;
		choiceEditor.setChoices(evalChoices);
	}

	/**
	 * Report any extensions that have parse errors
	 * @param errorList is the list of extensions (or null)
	 */
	private void reportExtensionErrors(ArrayList<String> errorList) {
		if (errorList == null) {
			return;
		}
		StringBuilder buffer = new StringBuilder();
		buffer.append("<HTML>User-defined extensions failed to parse: ");
		buffer.append("<ul>");
		for (String line : errorList) {
			buffer.append("<li>").append(line).append("</li>");
		}
		buffer.append("</ul>");
		buffer.append("See Program Options - Specification Extensions</HTML>");
		Msg.showError(BasicCompilerSpec.class, null, "Specification Extension Errors",
			buffer.toString());
	}

	/**
	 * Update this object with any program specific compiler specification extensions.
	 */
	protected void installExtensions() {
		int storedVersion = SpecExtension.getVersionCounter(program);
		if (storedVersion == versionCounter) {
			return;		// We currently match stored version, nothing to update
		}
		versionCounter = storedVersion;		// Update ourselves to stored version
		List<Pair<String, String>> pairList = SpecExtension.getCompilerSpecExtensions(program);
		if (pairList.isEmpty() && usermodels == null && pcodeInject.getProgramPayloads() == null) {
			return;		// No change
		}
		if (usermodels != null) {
			removeProgramMechanismPayloads(usermodels.values());
		}
		ArrayList<PrototypeModel> modelExtensions = new ArrayList<>();
		ArrayList<InjectPayloadSleigh> injectExtensions = new ArrayList<>();
		ArrayList<String> errorList = null;
		for (Pair<String, String> pair : pairList) {
			try {
				Object obj = SpecExtension.parseExtension(pair.first, pair.second, this, true);
				if (obj instanceof PrototypeModel) {
					PrototypeModel prototypeModel = (PrototypeModel) obj;
					modelExtensions.add(prototypeModel);
					errorList = addPrototypeError(errorList, prototypeModel);
				}
				else if (obj instanceof InjectPayloadSleigh) {
					InjectPayloadSleigh payload = (InjectPayloadSleigh) obj;
					injectExtensions.add(payload);
					errorList = addPayloadError(errorList, payload);
				}
			}
			catch (Exception e) {
				Msg.error(this,
					"Bad compiler spec extension: " + pair.first + " - " + e.getMessage());
			}
		}
		installPrototypeExtensions(modelExtensions);
		registerProgramInject(injectExtensions);
		updateModelChoices();
		reportExtensionErrors(errorList);
	}

	/**
	 * Build up the choice strings for all the evaluation methods
	 */
	private String[] establishEvaluationModelChoices(PrototypeModel defaultEval) {

		String[] evalChoices = new String[allmodels.length];
		// Make sure the default evaluation model occurs at the top of the list
		int defaultnum = -1;
		for (int i = 0; i < allmodels.length; ++i) {
			PrototypeModel curModel = allmodels[i];
			evalChoices[i] = curModel.getName();
			if (curModel == defaultEval) {
				defaultnum = i;
			}
		}

		if (defaultnum > 0) {
			String tmp = evalChoices[defaultnum];
			for (int i = defaultnum; i > 0; --i) {
				// Push everybody down to make room for default at top
				evalChoices[i] = evalChoices[i - 1];
			}
			evalChoices[0] = tmp;
		}
		return evalChoices;
	}

	@Override
	public PrototypeModel getPrototypeEvaluationModel(EvaluationModelType modelType) {

		Options options = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		switch (modelType) {
			case EVAL_CURRENT:
				String name =
					options.getString(EVALUATION_MODEL_PROPERTY_NAME, evalCurrentModel.getName());
				for (PrototypeModel model : allmodels) {		// Could be a merge model
					if (model.getName().equals(name)) {
						return model;
					}
				}
				break;
			case EVAL_CALLED:
				return evalCalledModel;		// TODO: Currently no option
		}
		return null;
	}

	/**
	 * Register program-specific compiler-spec options
	 */
	protected void registerProgramOptions() {

		// NOTE: Any changes to the option name/path must be handled carefully since
		// old property values will remain in the program.  There is currently no support
		// for upgrading/moving old property values.

		String[] evalChoices = establishEvaluationModelChoices(evalCurrentModel);
		Options decompilerPropertyList = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		decompilerPropertyList
				.setOptionsHelpLocation(new HelpLocation("DecompilePlugin", "ProgramOptions"));
		decompilerPropertyList.registerOption(EVALUATION_MODEL_PROPERTY_NAME,
			OptionType.STRING_TYPE, evalChoices[0],
			new HelpLocation("DecompilePlugin", "OptionProtoEval"),
			"Select the default function prototype/evaluation model to be used during Decompiler analysis",
			new StringWithChoicesEditor(evalChoices));

		// TODO: registration of DECOMPILER_OUTPUT_LANGUAGE option should be tied to Processor
		// and not presence of stored option.
		if (decompilerPropertyList.contains(DECOMPILER_OUTPUT_LANGUAGE)) {
			decompilerPropertyList.registerOption(DECOMPILER_OUTPUT_LANGUAGE, DECOMPILER_OUTPUT_DEF,
				null, DECOMPILER_OUTPUT_DESC);
		}

		Options analysisPropertyList =
			program.getOptions(Program.ANALYSIS_PROPERTIES + ".Decompiler Parameter ID");
		analysisPropertyList.createAlias(EVALUATION_MODEL_PROPERTY_NAME, decompilerPropertyList,
			EVALUATION_MODEL_PROPERTY_NAME);
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		ProgramCompilerSpec op2 = (ProgramCompilerSpec) obj;
		if (!SystemUtilities.isEqual(usermodels, op2.usermodels)) {
			return false;
		}
		return true;
	}

	/**
	 * Transition specified compiler specification langSpec into a program-specific 
	 * one which supports extensions.  If the specified langSpec is not a {@link BasicCompilerSpec}
	 * instance, the langSpec argument will be returned unmodified.
	 * @param program program to which langSpec applies
	 * @param langSpec initial compiler specification which does not support extensions.
	 * @return compiler specification to be used with program
	 */
	static CompilerSpec getProgramCompilerSpec(Program program, CompilerSpec langSpec) {
		if (langSpec instanceof ProgramCompilerSpec) {
			throw new IllegalArgumentException(
				"Cannot instantiate ProgramCompilerSpec from another ProgramCompilerSpec");
		}
		if (langSpec instanceof BasicCompilerSpec) {
			return new ProgramCompilerSpec(program, (BasicCompilerSpec) langSpec);
		}
		return langSpec;
	}
}
