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
//Example script for training random forests to find function starts
//@category    machineLearning

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.machinelearning.functionfinding.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;

//NOTE: This script is referenced by name in the help for the 
//RandomForestFunctionFinderPlugin.  If you change the name be
//sure to update the help.
public class FindFunctionsRFExampleScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		//get the parameters controlling how many models are trained and
		//what data is used to train/test them
		FunctionStartRFParams params = new FunctionStartRFParams(currentProgram);

		//maximum number of function starts to use in the training set
		//a warning will be issued if there are no functions left over for the test set
		params.setMaxStarts(1000);

		//minimum size of a function to be included in the training/test sets
		params.setMinFuncSize(16);

		//number of bytes before a function start
		params.setPreBytes(Arrays.asList(new Integer[] { 2, 8 }));

		//number of bytes after (and including) a function start
		params.setInitialBytes(Arrays.asList(new Integer[] { 8, 16 }));

		//number of non-starts to sample for each start in the training set
		params.setFactors(Arrays.asList(new Integer[] { 10, 50 }));

		//for every function start in the (test,training) set, add the code
		//units immediately before and immediately after to the (test,training) set
		//as non-starts. 
		params.setIncludePrecedingAndFollowing(true);

		//uncomment to include features for each bit rather than just byte-level features
		//params.setIncludeBitFeatures(true);

		//bound for reducing the size of the test sets
		long testSetMax = 1000000l;

		//this is where the trained models will go
		List<RandomForestRowObject> trainedModels = new ArrayList<>();

		RandomForestTrainingTask trainingTask = new RandomForestTrainingTask(currentProgram, params,
			r -> trainedModels.add(r), testSetMax);

		//launch the task to train the models in parallel
		trainingTask.run(monitor);

		//sort the models by the number of false positives (ascending)
		//if you actually need *unsigned* comparison it's likely that something has gone
		//horribly wrong
		Collections.sort(trainedModels,
			(x, y) -> Integer.compareUnsigned(x.getNumFalsePositives(), y.getNumFalsePositives()));

		//grab the model with the fewest false positives
		//note: there could be ties; could sort the winners by recall
		RandomForestRowObject best = trainedModels.get(0);

		printf(
			"Best model: pre-bytes: %d, initialBytes: %d, sampling factor: %d, false positives: %d," +
				" precision: %g, recall: %g\n",
			best.getNumPreBytes(), best.getNumInitialBytes(), best.getSamplingFactor(),
			best.getNumFalsePositives(), best.getPrecision(), best.getRecall());

		//to get more information about the test set errors, apply the model to the error set

		FunctionStartClassifier classifier = new FunctionStartClassifier(currentProgram, best,
			RandomForestFunctionFinderPlugin.FUNC_START);
		//uncomment to see false negatives as well
		//classifier.setProbabilityThreshold(0.0);

		Map<Address, Double> errors = classifier.classify(best.getTestErrors(), monitor);

		List<Entry<Address, Double>> falsePositives = errors.entrySet()
				.stream()
				.filter(x -> currentProgram.getFunctionManager().getFunctionAt(x.getKey()) == null)
				.sorted((x, y) -> Double.compare(y.getValue(), x.getValue()))
				.toList();

		//print out addresses of false positives
		printf("False positives:\n");
		falsePositives.forEach(x -> printf("  %s %g\n", x.getKey().toString(), x.getValue()));

		//show the true function starts most similar to one of the false positives
		if (!falsePositives.isEmpty()) {
			SimilarStartsFinder finder =
				new SimilarStartsFinder(currentProgram, currentProgram, best);
			List<SimilarStartRowObject> neighbors =
				finder.getSimilarFunctionStarts(falsePositives.get(0).getKey(), 10);
			printf("\nClosest function starts to false positive at %s :\n",
				falsePositives.get(0).getKey());
			neighbors.forEach(n -> printf("  %s %d\n", n.funcStart(), n.numAgreements()));
		}

		//grab the set of bytes in executable memory which are undefined (i.e., initialized but
		//not yet assigned to be code or data) or instructions which are not assigned to a function 
		//body
		//don't bother looking in small undefined ranges
		long minUndefinedRange = 16;
		GetAddressesToClassifyTask getAddressTask =
			new GetAddressesToClassifyTask(currentProgram, minUndefinedRange);
		getAddressTask.run(monitor);

		AddressSet toClassify = getAddressTask.getAddressesToClassify();

		Map<Address, Double> potentialStarts = classifier.classify(toClassify, monitor);

		//grab all of the addresses with probability of being a function start >= .7
		//and disassemble any that are currently undefined

		//block model is needed to get the interpretation of an address
		//e.g., undefined, block start, within block,...
		BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

//@formatter:off
		List<Address> addresses = potentialStarts.entrySet()
			.stream()
			.filter(x -> {return x.getValue() >= 0.7d;})
			.map(x -> x.getKey())
			.collect(Collectors.toList());
//@formatter:on

		AddressSet toDisassemble = new AddressSet();
		for (Address addr : addresses) {
			Interpretation inter =
				Interpretation.getInterpretation(currentProgram, addr, blockModel, monitor);
			if (inter.equals(Interpretation.UNDEFINED)) {
				toDisassemble.add(addr);
			}
		}

		//see DisassemblyAndApplyContextAction#actionPerfomed if you need to
		//apply context register values
		printf("Found %d addresses to disassemble\n", toDisassemble.getNumAddresses());
		DisassembleCommand cmd = new DisassembleCommand(toDisassemble, null, true);
		cmd.applyTo(currentProgram);

		//create functions at any address with probability of being a function start > .8, 
		//where an instruction exists,
		//which is defined as a BLOCK_START (so not already a function start)
		//and with no conditional flow references to it
		//FunctionStartRowObject represents a row in a table in the gui, but you don't
		//actually need the gui and it's a convenient container for information about an address

//@formatter:off
		List<FunctionStartRowObject> funcRows  = potentialStarts.entrySet()
			.stream()
			.filter(x -> {return x.getValue() >= 0.8d;})
			.map(x -> new FunctionStartRowObject(x.getKey(),x.getValue()))
			.collect(Collectors.toList());
//@formatter:on

		for (FunctionStartRowObject funcRow : funcRows) {
			funcRow.setCurrentInterpretation(Interpretation.getInterpretation(currentProgram,
				funcRow.getAddress(), blockModel, monitor));
			FunctionStartRowObject.setReferenceData(funcRow, currentProgram);
		}

		AddressSet entries = new AddressSet();
		funcRows.stream()
				.filter(x -> x.getCurrentInterpretation().equals(Interpretation.BLOCK_START))
				.filter(x -> x.getNumConditionalFlowRefs() == 0)
				.forEach(x -> entries.add(x.getAddress()));

		printf("Found %d addresses to create functions\n", entries.getNumAddresses());

		CreateFunctionCmd createCmd = new CreateFunctionCmd(entries);
		createCmd.applyTo(currentProgram);
	}

}
