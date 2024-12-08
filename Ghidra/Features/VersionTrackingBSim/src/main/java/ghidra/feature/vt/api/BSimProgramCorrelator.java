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
package ghidra.feature.vt.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import generic.jar.ResourceFile;
import generic.lsh.LSHMemoryModel;
import generic.lsh.vector.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.feature.vt.api.util.VTFunctionSizeUtil;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

/**
 * Correlator which discovers functional matches by comparing data-flow feature vectors.
 * An initial seed set of high confidence matches are chosen.  The match set is extended
 * from the seeds by using local neighborhoods around the accepted match to efficiently
 * discover new matches.
 */
public class BSimProgramCorrelator extends VTAbstractProgramCorrelator {

	private LSHVectorFactory vectorFactory;
	private static final int TIMEOUT = 60;
	public static final double SIMILARITY_THRESHOLD = 0.5;
	// note that the utils function strips out thunks now so we just set
	// minimum size to 0 assuming call graph will save us
	public static final int FUNCTION_MINIMUM_SIZE = 0;

	protected BSimProgramCorrelator(Program sourceProgram, AddressSetView sourceAddressSet,
			Program destinationProgram, AddressSetView destinationAddressSet, ToolOptions options) {
		super(sourceProgram, sourceAddressSet, destinationProgram, destinationAddressSet, options);
		vectorFactory = new WeightedLSHCosineVectorFactory();
	}

	@Override
	public String getName() {
		return BSimProgramCorrelatorFactory.NAME;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		ToolOptions options = getOptions();
		LSHMemoryModel model = options.getEnum(BSimProgramCorrelatorFactory.MEMORY_MODEL,
			BSimProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT);

		double confThreshold = options.getDouble(BSimProgramCorrelatorFactory.SEED_CONF_THRESHOLD,
			BSimProgramCorrelatorFactory.SEED_CONF_THRESHOLD_DEFAULT);
		double impThreshold = options.getDouble(BSimProgramCorrelatorFactory.IMPLICATION_THRESHOLD,
			BSimProgramCorrelatorFactory.IMPLICATION_THRESHOLD_DEFAULT);

		boolean useAcceptedMatchesAsSeeds =
			options.getBoolean(BSimProgramCorrelatorFactory.USE_ACCEPTED_MATCHES_AS_SEEDS,
				BSimProgramCorrelatorFactory.USE_ACCEPTED_MATCHES_AS_SEEDS_DEFAULT);

		boolean useNamespace = false;		// By default we don't have namespace info
		boolean useCallRefs = false;		// By default we use decompiler to generate callgraph

		List<FunctionPair> result;
		try {
			LanguageID id1 = getSourceProgram().getLanguageID();
			LanguageID id2 = getDestinationProgram().getLanguageID();
			//Use special weights for LSHCosineVectors
			ResourceFile defaultWeightsFile = GenSignatures.getWeightsFile(id1, id2);
			if (defaultWeightsFile == null) {

				// known limitation; hoped to be fixed in the future
				Msg.showWarn(this, null, "Cannot Compare Programs",
					"<html>Cannot currently compare programs with such different architectures.<br>" +
						"Source program is " + id1.getIdAsString() + "<br>" +
						"Destination program is " + id2.getIdAsString());
				return;
			}
			if (defaultWeightsFile.getName().contains("cpool")) {
				// With constant pool languages (Dalvik, JVM)
				useNamespace = true;			// We have reliable namespace info
				useCallRefs = true;				// We don't have absolute calls, use references
			}
			InputStream input = defaultWeightsFile.getInputStream();
			XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
				SpecXmlUtils.getXmlHandler(), false);
			vectorFactory.readWeights(parser);
			input.close();

			monitor.setMessage("Generating source dictionary");
			List<FunctionNode> rawSourceNodes =
				generateNodes(getSourceProgram(), getSourceAddressSet(), useCallRefs, monitor);
			FunctionNodeContainer sourceNodes =
				new FunctionNodeContainer(getSourceProgram(), rawSourceNodes);

			monitor.setMessage("Generating destination dictionary");
			List<FunctionNode> rawDestNodes = generateNodes(getDestinationProgram(),
				getDestinationAddressSet(), useCallRefs, monitor);
			FunctionNodeContainer destNodes =
				new FunctionNodeContainer(getDestinationProgram(), rawDestNodes);

			BSimProgramCorrelatorMatching omni =
				new BSimProgramCorrelatorMatching(sourceNodes, destNodes, vectorFactory,
					confThreshold, impThreshold, SIMILARITY_THRESHOLD, useNamespace, model);
			omni.discoverPotentialMatches(monitor);
			if (!omni.generateSeeds(matchSet, useAcceptedMatchesAsSeeds, monitor)) {
				Msg.info(this, "BSim Program Correlator could not find any seeds");
			}
			result = omni.doMatching(monitor);		//Do the matching!
		}
		catch (InterruptedException e) {
			Msg.error(this, "Error Correlating", e.getCause());
			CancelledException cancelledException = new CancelledException();
			cancelledException.initCause(e);
			throw cancelledException;
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (Exception e) {
			Msg.error(this, "Error Correlating", e.getCause());
			CancelledException cancelledException = new CancelledException();
			cancelledException.initCause(e);
			throw cancelledException;
		}

		wrapUp(result, matchSet, monitor);					// Display matches, print stuff, etc.

		return;
	}

	private static void addExternalFunctions(Program program, List<FunctionNode> list,
			LSHVectorFactory vFactory, TaskMonitor monitor) throws CancelledException {
		FunctionIterator iter = program.getFunctionManager().getExternalFunctions();
		// Create a generic feature vector to represent external functions
		int[] externalFeatures = new int[1];
		externalFeatures[0] = 0xfade5eed;
		LSHVector externalVector = vFactory.buildVector(externalFeatures);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Function func = iter.next();
			FunctionNode node = new FunctionNode(func, externalVector, new ArrayList<Address>());
			list.add(node);
		}
	}

	private List<FunctionNode> generateNodes(final Program program, AddressSetView addrSet,
			boolean useCallRefs, final TaskMonitor monitor)
			throws InterruptedException, CancelledException, Exception {

		monitor.checkCancelled();

		CachingPool<DecompInterface> decompilerPool = new CachingPool<DecompInterface>(
			new DecompilerFactory(program, vectorFactory.getSettings()));
		ParallelDecompilerCallback callback =
			new ParallelDecompilerCallback(decompilerPool, vectorFactory, useCallRefs);

		List<FunctionNode> results = null;
		try {
			AddressSetView refinedAddressSet = VTFunctionSizeUtil.minimumSizeFunctionFilter(program,
				addrSet, FUNCTION_MINIMUM_SIZE, monitor);
			results = ParallelDecompiler.decompileFunctions(callback, program, refinedAddressSet,
				monitor);
		}
		finally {
			decompilerPool.dispose();
		}

		addExternalFunctions(program, results, vectorFactory, monitor);

		monitor.setMessage("Collecting dictionary results");
		return results;
	}

	private static void wrapUp(List<FunctionPair> result, final VTMatchSet matchSet,
			final TaskMonitor monitor) throws CancelledException {

		//Populate the table with matches.
		monitor.setMessage("Adding results to database");
		monitor.setIndeterminate(false);
		monitor.initialize(result.size());
		int ii = 0;
		for (FunctionPair resMatch : result) {
			VTMatchInfo match = resMatch.getMatch(matchSet);
			++ii;
			if (ii % 1000 == 0) {
				monitor.checkCancelled();
				monitor.incrementProgress(1000);
			}
			matchSet.addMatch(match);
		}
		return;
	}

	/**
	 * Establish decompiler options for the feature vector calculation
	 * @param program is the specific program to decompile
	 * @return the formal options object
	 */
	private static DecompileOptions getDecompilerOptions(Program program) {
		DecompileOptions options = new DecompileOptions();
		options.setNoCastPrint(true);
		try {
			final PrototypeModel model = program.getCompilerSpec()
					.getPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT);
			options.setProtoEvalModel(model.getName());
		}
		catch (Exception e) {
			Msg.warn(BSimProgramCorrelator.class,
				"problem setting prototype evaluation model: " + e.getMessage());
		}
		options.setDefaultTimeout(TIMEOUT);
		return options;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;
		private int settings;

		DecompilerFactory(Program program, int set) {
			this.program = program;
			settings = set;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(getDecompilerOptions(program));
			decompiler.setSignatureSettings(settings);
			if (!decompiler.openProgram(program)) {
				throw new IOException(decompiler.getLastMessage());
			}
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private static class ParallelDecompilerCallback implements QCallback<Function, FunctionNode> {

		private LSHVectorFactory vectorFactory;
		private CachingPool<DecompInterface> pool;
		private boolean callsByReference;

		ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool,
				LSHVectorFactory vFactory, boolean refCalls) {
			vectorFactory = vFactory;
			this.pool = decompilerPool;
			callsByReference = refCalls;
		}

		private ArrayList<Address> getCallAddressesByReference(Function function,
				TaskMonitor monitor) throws CancelledException {
			ArrayList<Address> resultList = new ArrayList<Address>();
			Program program = function.getProgram();
			ReferenceManager referenceManager = program.getReferenceManager();
			AddressSetView addresses = function.getBody();
			AddressIterator addressIterator = addresses.getAddresses(true);
			while (addressIterator.hasNext()) {
				monitor.checkCancelled();
				Address address = addressIterator.next();
				Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
				if (referencesFrom != null) {
					for (Reference reference : referencesFrom) {
						if (reference.getReferenceType().isCall()) {
							resultList.add(reference.getToAddress());
						}
					}
				}
			}
			return resultList;
		}

		@Override
		public FunctionNode process(Function function, TaskMonitor monitor) throws Exception {

			monitor.checkCancelled();
			DecompInterface decompiler = pool.get();
			try {
				LSHVector vec = null;
				ArrayList<Address> callAddresses = null;
				SignatureResult sigres =
					decompiler.generateSignatures(function, !callsByReference, TIMEOUT, monitor);
				if (sigres == null) {
					callAddresses = new ArrayList<Address>();
				}
				else {
					vec = vectorFactory.buildVector(sigres.features);
					if (callsByReference) {
						callAddresses = getCallAddressesByReference(function, monitor);
					}
					else {
						callAddresses = sigres.calllist;	//It will take a second pass through the data to figure out how the call graph fits together.
					}
				}
				FunctionNode res = new FunctionNode(function, vec, callAddresses);
				if (res.getVector() == null) {
					String errmsg = decompiler.getLastMessage();
					if (errmsg.startsWith("Bad command")) {
						throw new DecompileException(BSimProgramCorrelatorFactory.NAME, errmsg);
					}
				}
				return res;
			}
			finally {
				pool.release(decompiler);
			}
		}
	}
}
