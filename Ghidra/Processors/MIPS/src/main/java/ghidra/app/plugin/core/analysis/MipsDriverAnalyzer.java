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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * MIPS Driver Analyzer (opt-in, deep, slow, and correct).
 *
 * Purpose: Whole-program reasoning for MIPS driver/firmware code. Resolves indirect calls,
 * infers parameter counts by caller consensus and body evidence, types function-pointer returns,
 * synthesizes/assigns struct field types for function pointer members, and classifies trampolines.
 *
 * This analyzer is intentionally late and heavy. It should be disabled by default and run
 * only when the user opts in for deeper analysis.
 */
public class MipsDriverAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "MIPS Driver Analyzer";
    private static final String DESCRIPTION =
        "Deep, opt-in analyzer for MIPS programs: resolves indirect calls, infers params, and types function-pointer fields.";

    // Configuration option keys
    private static final String OPTION_NEAR_WINDOW = "Near Window Size";
    private static final String OPTION_A3_THRESHOLD = "A3 Promotion Threshold";
    private static final String OPTION_ENABLE_STRUCT_SYNTHESIS = "Enable Struct Field Synthesis";
    private static final String OPTION_MAX_SYNTHETIC_TYPES = "Max Synthetic Types Per Function";
    private static final String OPTION_ENABLE_ZERO_ARG_COLLAPSE = "Enable Zero-Arg Collapse";
    private static final String OPTION_VERBOSE_LOGGING = "Verbose Debug Logging";

    // Default values
    private static final int DEFAULT_NEAR_WINDOW = 5;
    private static final int DEFAULT_A3_THRESHOLD = 2;
    private static final boolean DEFAULT_ENABLE_STRUCT_SYNTHESIS = true;
    private static final int DEFAULT_MAX_SYNTHETIC_TYPES = 50;
    private static final boolean DEFAULT_ENABLE_ZERO_ARG_COLLAPSE = true;
    private static final boolean DEFAULT_VERBOSE_LOGGING = false;

    // Configuration values
    private int nearWindow = DEFAULT_NEAR_WINDOW;
    private int a3Threshold = DEFAULT_A3_THRESHOLD;
    private boolean enableStructSynthesis = DEFAULT_ENABLE_STRUCT_SYNTHESIS;
    private int maxSyntheticTypes = DEFAULT_MAX_SYNTHETIC_TYPES;
    private boolean enableZeroArgCollapse = DEFAULT_ENABLE_ZERO_ARG_COLLAPSE;
    private boolean verboseLogging = DEFAULT_VERBOSE_LOGGING;

    // Statistics
    private int jalrSitesScanned = 0;
    private int jrSitesScanned = 0;
    private int returnPointerFunctionsTyped = 0;
    private int trampolinesDetected = 0;
    private int functionsParamsExpanded = 0;
    private int functionsParamsCollapsed = 0;
    private int structFieldsTyped = 0;

    public MipsDriverAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        // Run after type/propagation so we can leverage existing references and pointer info
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        // Opt-in: disabled by default
        setDefaultEnablement(false);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && program.getLanguage().getProcessor().equals(
            Processor.findOrPossiblyCreateProcessor("MIPS"));
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_NEAR_WINDOW, DEFAULT_NEAR_WINDOW, null,
            "Number of instructions before/after call site to examine for argument evidence");
        options.registerOption(OPTION_A3_THRESHOLD, DEFAULT_A3_THRESHOLD, null,
            "Minimum number of call sites required to promote function to 4 parameters");
        options.registerOption(OPTION_ENABLE_STRUCT_SYNTHESIS, DEFAULT_ENABLE_STRUCT_SYNTHESIS, null,
            "Enable synthesis of struct types for function pointer fields");
        options.registerOption(OPTION_MAX_SYNTHETIC_TYPES, DEFAULT_MAX_SYNTHETIC_TYPES, null,
            "Maximum number of synthetic struct types to create per function");
        options.registerOption(OPTION_ENABLE_ZERO_ARG_COLLAPSE, DEFAULT_ENABLE_ZERO_ARG_COLLAPSE, null,
            "Enable collapsing functions to zero parameters when no callers pass arguments");
        options.registerOption(OPTION_VERBOSE_LOGGING, DEFAULT_VERBOSE_LOGGING, null,
            "Enable verbose debug logging for detailed analysis information");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        nearWindow = options.getInt(OPTION_NEAR_WINDOW, DEFAULT_NEAR_WINDOW);
        a3Threshold = options.getInt(OPTION_A3_THRESHOLD, DEFAULT_A3_THRESHOLD);
        enableStructSynthesis = options.getBoolean(OPTION_ENABLE_STRUCT_SYNTHESIS, DEFAULT_ENABLE_STRUCT_SYNTHESIS);
        maxSyntheticTypes = options.getInt(OPTION_MAX_SYNTHETIC_TYPES, DEFAULT_MAX_SYNTHETIC_TYPES);
        enableZeroArgCollapse = options.getBoolean(OPTION_ENABLE_ZERO_ARG_COLLAPSE, DEFAULT_ENABLE_ZERO_ARG_COLLAPSE);
        verboseLogging = options.getBoolean(OPTION_VERBOSE_LOGGING, DEFAULT_VERBOSE_LOGGING);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        long startTime = System.currentTimeMillis();
        Msg.info(this, "MIPS Driver Analyzer starting (opt-in, deep mode)...");

        // Reset statistics
        resetStatistics();

        try {
            // Phase 1: Discovery Scan - enumerate jalr/jr sites
            monitor.setMessage("Phase 1: Discovering indirect call sites...");
            List<IndirectCallSite> callSites = discoverIndirectCallSites(program, set, monitor);

            // Phase 2: Return-Pointer Classification
            monitor.setMessage("Phase 2: Classifying return-pointer functions...");
            classifyReturnPointerFunctions(program, callSites, monitor);

            // Phase 3: Trampoline Detection and Typing
            monitor.setMessage("Phase 3: Detecting and typing trampolines...");
            detectAndTypeTrampolines(program, callSites, monitor);

            // Phase 4: Parameter Inference
            monitor.setMessage("Phase 4: Inferring parameter counts...");
            inferParameterCounts(program, monitor);

            // Phase 5: Table/Vector Typing
            if (enableStructSynthesis) {
                monitor.setMessage("Phase 5: Typing function pointer tables...");
                typeFunctionPointerTables(program, monitor);
            }

            // Phase 6: Reporting
            long elapsed = System.currentTimeMillis() - startTime;
            reportResults(elapsed);

            return hasChanges();

        } catch (Exception e) {
            Msg.error(this, "Error in MIPS Driver Analyzer", e);
            log.appendException(e);
            return false;
        }
    }

    /**
     * Helper class to represent an indirect call site (jalr/jr instruction)
     */
    private static class IndirectCallSite {
        final Address address;
        final Instruction instruction;
        final Register targetRegister;
        final boolean isJalr;  // true for jalr, false for jr
        final boolean isReturnPointerPattern;  // true if target is v0/v1

        IndirectCallSite(Address addr, Instruction instr, Register targetReg, boolean jalr) {
            this.address = addr;
            this.instruction = instr;
            this.targetRegister = targetReg;
            this.isJalr = jalr;
            this.isReturnPointerPattern = targetReg != null &&
                (targetReg.getName().equals("v0") || targetReg.getName().equals("v1"));
        }
    }

    /**
     * Helper class to track parameter usage evidence at call sites
     */
    private static class ParameterEvidence {
        int a0Count = 0;
        int a1Count = 0;
        int a2Count = 0;
        int a3Count = 0;
        int totalCallSites = 0;

        void recordCallSite(int maxArgRegUsed) {
            totalCallSites++;
            if (maxArgRegUsed >= 0) a0Count++;
            if (maxArgRegUsed >= 1) a1Count++;
            if (maxArgRegUsed >= 2) a2Count++;
            if (maxArgRegUsed >= 3) a3Count++;
        }

        int inferParameterCount(int a3Threshold) {
            // Require stronger evidence for a3 (4 params)
            if (a3Count >= a3Threshold) return 4;
            if (a2Count > 0) return 3;
            if (a1Count > 0) return 2;
            if (a0Count > 0) return 1;
            return 0;
        }
    }

    /**
     * Helper class to track analysis findings for reporting
     */
    private static class AnalysisFinding {
        final String category;
        final Address address;
        final String functionName;
        final String action;
        final String evidence;

        AnalysisFinding(String category, Address addr, String funcName, String action, String evidence) {
            this.category = category;
            this.address = addr;
            this.functionName = funcName;
            this.action = action;
            this.evidence = evidence;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s @ %s: %s (Evidence: %s)",
                category, functionName, address, action, evidence);
        }
    }

    // List to track detailed findings
    private List<AnalysisFinding> findings = new ArrayList<>();

    /**
     * Reset statistics counters
     */
    private void resetStatistics() {
        jalrSitesScanned = 0;
        jrSitesScanned = 0;
        returnPointerFunctionsTyped = 0;
        trampolinesDetected = 0;
        functionsParamsExpanded = 0;
        functionsParamsCollapsed = 0;
        structFieldsTyped = 0;
        findings.clear();
    }

    /**
     * Record an analysis finding
     */
    private void recordFinding(String category, Address addr, String funcName, String action, String evidence) {
        if (verboseLogging) {
            findings.add(new AnalysisFinding(category, addr, funcName, action, evidence));
        }
    }

    /**
     * Check if any changes were made
     */
    private boolean hasChanges() {
        return returnPointerFunctionsTyped > 0 ||
               trampolinesDetected > 0 ||
               functionsParamsExpanded > 0 ||
               functionsParamsCollapsed > 0 ||
               structFieldsTyped > 0;
    }

    /**
     * Phase 1: Discover all jalr/jr sites in the program
     */
    private List<IndirectCallSite> discoverIndirectCallSites(Program program, AddressSetView set,
            TaskMonitor monitor) throws CancelledException {

        List<IndirectCallSite> sites = new ArrayList<>();
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(set, true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            monitor.checkCancelled();
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();

            // Check for jalr or jr (including microMIPS variants with underscore prefix)
            boolean isJalr = mnemonic.equals("jalr") || mnemonic.equals("_jalr");
            boolean isJr = mnemonic.equals("jr") || mnemonic.equals("_jr");

            if (isJalr || isJr) {
                Register targetReg = getJumpTargetRegister(instr);
                if (targetReg != null) {
                    sites.add(new IndirectCallSite(instr.getAddress(), instr, targetReg, isJalr));
                    if (isJalr) {
                        jalrSitesScanned++;
                    } else {
                        jrSitesScanned++;
                    }

                    if (verboseLogging) {
                        Msg.debug(this, String.format("Found %s at %s, target: %s",
                            mnemonic, instr.getAddress(), targetReg.getName()));
                    }
                }
            }
        }

        Msg.info(this, String.format("Discovery: Found %d jalr and %d jr sites",
            jalrSitesScanned, jrSitesScanned));

        return sites;
    }

    /**
     * Extract the jump target register from a jalr/jr instruction.
     * Handles various MIPS instruction formats.
     */
    private Register getJumpTargetRegister(Instruction instr) {
        // Try to get registers from operands
        // jalr can be: jalr $ra, $v0  or  jalr $v0
        // jr is typically: jr $v0

        Register r0 = instr.getRegister(0);
        Register r1 = instr.getRegister(1);

        // Prefer non-$ra register (the actual jump target)
        if (r1 != null && !"ra".equals(r1.getName())) {
            return r1;
        }
        if (r0 != null && !"ra".equals(r0.getName())) {
            return r0;
        }
        // Fallback to any register found
        if (r1 != null) {
            return r1;
        }
        return r0;
    }

    /**
     * Phase 2: Classify functions that return function pointers (v0/v1 jalr/jr pattern)
     */
    private void classifyReturnPointerFunctions(Program program, List<IndirectCallSite> callSites,
            TaskMonitor monitor) throws CancelledException {

        DataTypeManager dtMgr = program.getDataTypeManager();

        int txId = program.startTransaction("Classify Return-Pointer Functions");
        try {
            for (IndirectCallSite site : callSites) {
                monitor.checkCancelled();

                if (!site.isReturnPointerPattern) {
                    continue;  // Only process v0/v1 patterns
                }

                // Look backward to find the function call that populated v0/v1
                Function calledFunc = findFunctionPopulatingRegister(program, site.address,
                    site.targetRegister, 20);  // Look back up to 20 instructions

                if (calledFunc != null && !calledFunc.hasCustomVariableStorage()) {
                    // Set return type to function pointer
                    DataType currentReturn = calledFunc.getReturnType();
                    if (!(currentReturn instanceof FunctionDefinition) &&
                        !(currentReturn instanceof Pointer)) {

                        try {
                            // Create a generic function pointer type
                            FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType("fp_sig");
                            PointerDataType funcPtr = new PointerDataType(funcDef, dtMgr);

                            calledFunc.setReturnType(funcPtr, SourceType.ANALYSIS);
                            returnPointerFunctionsTyped++;

                            recordFinding("Return-Pointer", calledFunc.getEntryPoint(), calledFunc.getName(),
                                "Set return type to function pointer",
                                String.format("Used by jalr/jr at %s via %s", site.address, site.targetRegister.getName()));

                            if (verboseLogging) {
                                Msg.debug(this, String.format("Set return type of %s to function pointer",
                                    calledFunc.getName()));
                            }
                        } catch (InvalidInputException e) {
                            Msg.warn(this, "Failed to set return type for " + calledFunc.getName(), e);
                        }
                    }
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }

        Msg.info(this, String.format("Return-Pointer Classification: Typed %d functions",
            returnPointerFunctionsTyped));
    }

    /**
     * Find the function call that populates a given register by looking backward from an address
     */
    private Function findFunctionPopulatingRegister(Program program, Address fromAddr,
            Register targetReg, int maxLookback) {

        Listing listing = program.getListing();
        FunctionManager funcMgr = program.getFunctionManager();
        Address current = fromAddr;

        for (int i = 0; i < maxLookback; i++) {
            Instruction instr = listing.getInstructionBefore(current);
            if (instr == null) {
                break;
            }
            current = instr.getAddress();

            // Check if this is a function call
            FlowType flowType = instr.getFlowType();
            if (flowType.isCall()) {
                // Check if the call writes to our target register
                // In MIPS, function return values go to v0/v1
                if (targetReg.getName().equals("v0") || targetReg.getName().equals("v1")) {
                    // Get the called function
                    Address[] flows = instr.getFlows();
                    if (flows != null && flows.length > 0) {
                        Function calledFunc = funcMgr.getFunctionAt(flows[0]);
                        if (calledFunc != null) {
                            return calledFunc;
                        }
                    }
                }
            }

            // Check if this instruction writes to the target register (would break the chain)
            Object[] results = instr.getResultObjects();
            if (results != null) {
                for (Object result : results) {
                    if (result instanceof Register) {
                        Register resultReg = (Register) result;
                        if (resultReg.equals(targetReg)) {
                            // Register is overwritten, stop looking
                            return null;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Phase 3: Detect trampolines and apply flow overrides
     */
    private void detectAndTypeTrampolines(Program program, List<IndirectCallSite> callSites,
            TaskMonitor monitor) throws CancelledException {

        DataTypeManager dtMgr = program.getDataTypeManager();
        int txId = program.startTransaction("Detect and Type Trampolines");
        try {
            for (IndirectCallSite site : callSites) {
                monitor.checkCancelled();

                // Skip return-pointer patterns (handled in Phase 2)
                if (site.isReturnPointerPattern) {
                    continue;
                }

                // For jalr (indirect calls), try to type the struct field if loaded from memory
                if (site.isJalr && enableStructSynthesis) {
                    typeIndirectCallStructField(program, site, dtMgr);
                }

                // Check if this looks like a trampoline:
                // - jr (not jalr) suggests tail call
                // - Target register loaded from parameter or memory
                if (!site.isJalr) {
                    boolean isTrampoline = analyzeForTrampolinePattern(program, site);
                    if (isTrampoline) {
                        // Apply CALL_RETURN flow override
                        try {
                            site.instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                            trampolinesDetected++;

                            Function containingFunc = program.getFunctionManager().getFunctionContaining(site.address);
                            String funcName = containingFunc != null ? containingFunc.getName() : "unknown";

                            recordFinding("Trampoline", site.address, funcName,
                                "Applied CALL_RETURN flow override",
                                String.format("jr %s pattern detected", site.targetRegister.getName()));

                            if (verboseLogging) {
                                Msg.debug(this, String.format("Marked trampoline at %s", site.address));
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "Failed to set flow override at " + site.address, e);
                        }
                    }
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }

        Msg.info(this, String.format("Trampoline Detection: Found %d trampolines", trampolinesDetected));
    }

    /**
     * Type struct fields for indirect calls loaded from memory
     */
    private void typeIndirectCallStructField(Program program, IndirectCallSite site, DataTypeManager dtMgr) {
        // Look backward to find the load instruction that populated the target register
        Listing listing = program.getListing();
        Address current = site.address;
        Register targetReg = site.targetRegister;

        for (int i = 0; i < 10; i++) {
            Instruction instr = listing.getInstructionBefore(current);
            if (instr == null) {
                break;
            }
            current = instr.getAddress();

            String mnemonic = instr.getMnemonicString();

            // Check for load instructions (lw, ld, etc.)
            if (mnemonic.startsWith("lw") || mnemonic.startsWith("ld") ||
                mnemonic.equals("_lw") || mnemonic.equals("_ld")) {

                // Check if this loads into our target register
                Register destReg = instr.getRegister(0);
                if (destReg != null && destReg.equals(targetReg)) {
                    // This is the load that populates the function pointer
                    // Try to infer parameter count for this call
                    int paramCount = analyzeCallSiteArguments(program, site.instruction);

                    // Create a function signature with the inferred parameter count
                    try {
                        FunctionDefinitionDataType funcDef = createFunctionSignature(
                            "fp_sig" + (paramCount + 1), paramCount + 1, dtMgr);
                        PointerDataType funcPtr = new PointerDataType(funcDef, dtMgr);

                        // Try to apply this type to the memory location being loaded
                        Reference[] refs = instr.getReferencesFrom();
                        if (refs != null && refs.length > 0) {
                            for (Reference ref : refs) {
                                if (ref.isMemoryReference()) {
                                    Address memAddr = ref.getToAddress();
                                    if (memAddr != null) {
                                        try {
                                            Data existingData = listing.getDataAt(memAddr);
                                            if (existingData == null ||
                                                !(existingData.getDataType() instanceof FunctionDefinition)) {

                                                // Clear and create new data
                                                int ptrSize = program.getDefaultPointerSize();
                                                listing.clearCodeUnits(memAddr, memAddr.add(ptrSize - 1), false);
                                                listing.createData(memAddr, funcPtr, ptrSize);
                                                structFieldsTyped++;

                                                if (verboseLogging) {
                                                    Msg.debug(this, String.format(
                                                        "Typed function pointer at %s with %d params (called from %s)",
                                                        memAddr, paramCount + 1, site.address));
                                                }
                                            }
                                        } catch (Exception e) {
                                            // Silently ignore typing failures
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Silently ignore signature creation failures
                    }

                    break;  // Found the load, stop looking
                }
            }
        }
    }

    /**
     * Create a function signature with the specified number of parameters
     */
    private FunctionDefinitionDataType createFunctionSignature(String name, int paramCount,
            DataTypeManager dtMgr) {

        FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
        funcDef.setReturnType(VoidDataType.dataType);

        if (paramCount > 0) {
            ParameterDefinition[] params = new ParameterDefinition[paramCount];
            for (int i = 0; i < paramCount; i++) {
                params[i] = new ParameterDefinitionImpl(
                    "param_" + (i + 1),
                    Undefined4DataType.dataType,
                    "");
            }
            funcDef.setArguments(params);
        }

        return funcDef;
    }

    /**
     * Analyze if an indirect call site is a trampoline pattern
     */
    private boolean analyzeForTrampolinePattern(Program program, IndirectCallSite site) {
        // Look backward to see if target register is loaded from a parameter or memory
        Listing listing = program.getListing();
        Address current = site.address;
        Register targetReg = site.targetRegister;

        // Simple heuristic: look back up to 10 instructions
        for (int i = 0; i < 10; i++) {
            Instruction instr = listing.getInstructionBefore(current);
            if (instr == null) {
                break;
            }
            current = instr.getAddress();

            String mnemonic = instr.getMnemonicString();

            // Check for load instructions (lw, ld, etc.)
            if (mnemonic.startsWith("lw") || mnemonic.startsWith("ld") ||
                mnemonic.equals("_lw") || mnemonic.equals("_ld")) {

                // Check if this loads into our target register
                Register destReg = instr.getRegister(0);
                if (destReg != null && destReg.equals(targetReg)) {
                    // This is likely a trampoline: loading function pointer from memory
                    return true;
                }
            }

            // Check for move-like instructions from parameter registers
            if (mnemonic.equals("move") || mnemonic.equals("or") ||
                mnemonic.equals("addu") || mnemonic.equals("daddu")) {

                Register destReg = instr.getRegister(0);
                if (destReg != null && destReg.equals(targetReg)) {
                    // Check if source is a parameter register (a0-a3)
                    Register srcReg = instr.getRegister(1);
                    if (srcReg != null) {
                        String srcName = srcReg.getName();
                        if (srcName.equals("a0") || srcName.equals("a1") ||
                            srcName.equals("a2") || srcName.equals("a3")) {
                            // Trampoline: forwarding parameter as function pointer
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Phase 4: Infer parameter counts using caller consensus and body evidence
     */
    private void inferParameterCounts(Program program, TaskMonitor monitor) throws CancelledException {
        // Build evidence map for all functions
        Map<Function, ParameterEvidence> evidenceMap = new HashMap<>();

        // Scan all call sites to gather caller consensus
        monitor.setMessage("Gathering caller consensus...");
        gatherCallerConsensus(program, evidenceMap, monitor);

        // Apply parameter count updates
        monitor.setMessage("Applying parameter count updates...");
        int txId = program.startTransaction("Infer Parameter Counts");
        try {
            for (Map.Entry<Function, ParameterEvidence> entry : evidenceMap.entrySet()) {
                monitor.checkCancelled();

                Function func = entry.getKey();
                ParameterEvidence evidence = entry.getValue();

                // Skip USER_DEFINED functions
                if (func.getSignatureSource() == SourceType.USER_DEFINED) {
                    continue;
                }

                int currentParamCount = func.getParameterCount();
                int callerInferredCount = evidence.inferParameterCount(a3Threshold);

                // Also check body-based evidence
                int bodyInferredCount = analyzeFunctionBodyForParameters(program, func);

                // Use the MAXIMUM of caller consensus and body evidence
                // - Body evidence: if the function uses a parameter (directly or pass-through), it exists
                // - Caller evidence: if callers consistently pass parameters, they likely exist
                // Both sources are valuable and we trust whichever shows more parameters
                int inferredCount = Math.max(callerInferredCount, bodyInferredCount + 1);

                // Check for zero-arg collapse
                if (enableZeroArgCollapse && inferredCount == 0 && currentParamCount > 0) {
                    // Collapse to zero parameters
                    try {
                        List<Parameter> emptyParams = new ArrayList<>();
                        // Use DEFAULT source type to avoid "parameter storage is locked" warnings
                        func.updateFunction(null, null, emptyParams,
                            FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.DEFAULT);
                        functionsParamsCollapsed++;

                        recordFinding("Parameter-Collapse", func.getEntryPoint(), func.getName(),
                            String.format("Collapsed from %d to 0 parameters", currentParamCount),
                            String.format("No argument usage detected across %d call sites", evidence.totalCallSites));

                        if (verboseLogging) {
                            Msg.debug(this, String.format("Collapsed %s to 0 parameters", func.getName()));
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to collapse parameters for " + func.getName(), e);
                    }
                } else if (inferredCount > currentParamCount) {
                    // Expand parameters
                    try {
                        List<Parameter> params = new ArrayList<>();
                        for (int i = 0; i < inferredCount; i++) {
                            String paramName = "param_" + (i + 1);
                            DataType paramType = Undefined4DataType.dataType;
                            params.add(new ParameterImpl(paramName, paramType, program));
                        }

                        // Use DEFAULT source type to avoid "parameter storage is locked" warnings
                        // This allows the decompiler to properly apply the calling convention
                        func.updateFunction(null, null, params,
                            FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.DEFAULT);
                        functionsParamsExpanded++;

                        recordFinding("Parameter-Expand", func.getEntryPoint(), func.getName(),
                            String.format("Expanded from %d to %d parameters", currentParamCount, inferredCount),
                            String.format("Caller consensus: a0=%d a1=%d a2=%d a3=%d across %d sites",
                                evidence.a0Count, evidence.a1Count, evidence.a2Count, evidence.a3Count, evidence.totalCallSites));

                        if (verboseLogging) {
                            Msg.debug(this, String.format("Expanded %s to %d parameters",
                                func.getName(), inferredCount));
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to expand parameters for " + func.getName(), e);
                    }
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }

        Msg.info(this, String.format("Parameter Inference: Expanded %d functions, Collapsed %d functions",
            functionsParamsExpanded, functionsParamsCollapsed));
    }

    /**
     * Gather caller consensus by analyzing all call sites
     */
    private void gatherCallerConsensus(Program program, Map<Function, ParameterEvidence> evidenceMap,
            TaskMonitor monitor) throws CancelledException {

        FunctionManager funcMgr = program.getFunctionManager();
        Listing listing = program.getListing();

        // Iterate through all functions
        for (Function func : funcMgr.getFunctions(true)) {
            monitor.checkCancelled();

            // Get all references to this function
            Set<Address> callers = new HashSet<>();
            for (Reference ref : program.getReferenceManager().getReferencesTo(func.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) {
                    callers.add(ref.getFromAddress());
                }
            }

            ParameterEvidence evidence = evidenceMap.computeIfAbsent(func, k -> new ParameterEvidence());

            // Analyze each call site
            for (Address callAddr : callers) {
                Instruction callInstr = listing.getInstructionAt(callAddr);
                if (callInstr == null) {
                    continue;
                }

                int maxArgReg = analyzeCallSiteArguments(program, callInstr);
                evidence.recordCallSite(maxArgReg);
            }

            // Also analyze function body for parameter usage
            int bodyParamCount = analyzeFunctionBodyForParameters(program, func);
            if (bodyParamCount >= 0) {
                // Body evidence: record as if we saw a call site with this many args
                evidence.recordCallSite(bodyParamCount);

                if (verboseLogging) {
                    Msg.debug(this, String.format("Body analysis for %s suggests %d parameters",
                        func.getName(), bodyParamCount + 1));
                }
            }
        }
    }

    /**
     * Analyze function body to detect which argument registers are used.
     * Returns the highest argument register index used (-1 for none, 0 for a0, 1 for a1, etc.)
     *
     * This now includes pass-through parameter detection: parameters that are received
     * and passed to another function without being modified.
     */
    private int analyzeFunctionBodyForParameters(Program program, Function func) {
        if (func == null || func.isThunk() || func.isExternal()) {
            return -1;
        }

        Register[] argRegs = {
            program.getRegister("a0"),
            program.getRegister("a1"),
            program.getRegister("a2"),
            program.getRegister("a3")
        };

        if (argRegs[0] == null) {
            return -1;
        }

        // Track which argument registers are read before being written
        boolean[] argRegRead = new boolean[4];
        boolean[] argRegWritten = new boolean[4];
        boolean[] argRegPassThrough = new boolean[4];

        Listing listing = program.getListing();
        AddressSetView body = func.getBody();
        InstructionIterator instructions = listing.getInstructions(body, true);

        int instrCount = 0;
        int maxInstrToCheck = 100;  // Increased to catch pass-through patterns

        while (instructions.hasNext() && instrCount < maxInstrToCheck) {
            Instruction instr = instructions.next();
            instrCount++;

            // Check if this is a call instruction (jal, jalr)
            FlowType flowType = instr.getFlowType();
            if (flowType.isCall()) {
                // Check which argument registers are still unwritten at this call
                // These are likely pass-through parameters
                Object[] inputs = instr.getInputObjects();
                if (inputs != null) {
                    for (Object input : inputs) {
                        if (input instanceof Register) {
                            Register reg = (Register) input;
                            for (int i = 0; i < argRegs.length; i++) {
                                if (argRegs[i] != null && reg.equals(argRegs[i]) && !argRegWritten[i]) {
                                    // This arg register is used in a call without being written first
                                    // It's a pass-through parameter
                                    argRegPassThrough[i] = true;
                                    argRegRead[i] = true;
                                }
                            }
                        }
                    }
                }

                // Also check the near-window before the call for argument setup
                // Arguments set up right before a call are likely pass-throughs
                Address callAddr = instr.getAddress();
                for (int lookback = 0; lookback < 5; lookback++) {
                    Instruction prevInstr = listing.getInstructionBefore(callAddr);
                    if (prevInstr == null) break;
                    callAddr = prevInstr.getAddress();

                    // Check if this instruction reads an arg register (without writing it first)
                    Object[] prevInputs = prevInstr.getInputObjects();
                    if (prevInputs != null) {
                        for (Object input : prevInputs) {
                            if (input instanceof Register) {
                                Register reg = (Register) input;
                                for (int i = 0; i < argRegs.length; i++) {
                                    if (argRegs[i] != null && reg.equals(argRegs[i]) && !argRegWritten[i]) {
                                        argRegPassThrough[i] = true;
                                        argRegRead[i] = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check input operands (reads)
            Object[] inputs = instr.getInputObjects();
            if (inputs != null) {
                for (Object input : inputs) {
                    if (input instanceof Register) {
                        Register reg = (Register) input;
                        for (int i = 0; i < argRegs.length; i++) {
                            if (argRegs[i] != null && reg.equals(argRegs[i]) && !argRegWritten[i]) {
                                argRegRead[i] = true;
                            }
                        }
                    }
                }
            }

            // Check result operands (writes)
            Object[] results = instr.getResultObjects();
            if (results != null) {
                for (Object result : results) {
                    if (result instanceof Register) {
                        Register reg = (Register) result;
                        for (int i = 0; i < argRegs.length; i++) {
                            if (argRegs[i] != null && reg.equals(argRegs[i])) {
                                argRegWritten[i] = true;
                            }
                        }
                    }
                }
            }
        }

        // Determine highest argument register that was read before written
        // This includes both direct usage and pass-through
        int maxArgUsed = -1;
        for (int i = 0; i < argRegRead.length; i++) {
            if (argRegRead[i]) {
                maxArgUsed = i;
            }
        }

        if (verboseLogging && maxArgUsed >= 0) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Body analysis for %s: max arg = a%d",
                func.getName(), maxArgUsed));
            sb.append(" (");
            for (int i = 0; i <= maxArgUsed; i++) {
                if (argRegPassThrough[i]) {
                    sb.append(String.format("a%d=pass-through ", i));
                } else if (argRegRead[i]) {
                    sb.append(String.format("a%d=used ", i));
                }
            }
            sb.append(")");
            Msg.debug(this, sb.toString());
        }

        return maxArgUsed;
    }

    /**
     * Analyze a call site to determine which argument registers are used
     * Returns the highest argument register index used (-1 for none, 0 for a0, 1 for a1, etc.)
     */
    private int analyzeCallSiteArguments(Program program, Instruction callInstr) {
        Listing listing = program.getListing();
        Register[] argRegs = {
            program.getRegister("a0"),
            program.getRegister("a1"),
            program.getRegister("a2"),
            program.getRegister("a3")
        };

        if (argRegs[0] == null) {
            return -1;  // Can't find argument registers
        }

        int maxArgUsed = -1;
        boolean[] argRegSet = new boolean[4];

        // Look in the near window before the call (including delay slot)
        // Track the most recent write to each argument register
        Address current = callInstr.getAddress();
        Address[] lastWriteAddr = new Address[4];

        for (int i = 0; i < nearWindow; i++) {
            Instruction instr = listing.getInstructionBefore(current);
            if (instr == null) {
                break;
            }
            current = instr.getAddress();

            // Check if this instruction writes to any argument register
            Object[] results = instr.getResultObjects();
            if (results != null) {
                for (Object result : results) {
                    if (result instanceof Register) {
                        Register reg = (Register) result;
                        for (int j = 0; j < argRegs.length; j++) {
                            if (argRegs[j] != null && reg.equals(argRegs[j])) {
                                // Record this write if we haven't seen one yet
                                if (!argRegSet[j]) {
                                    argRegSet[j] = true;
                                    lastWriteAddr[j] = instr.getAddress();
                                }
                            }
                        }
                    }
                }
            }

            // If we hit another call, check if the argument registers we've seen
            // were written AFTER that call (meaning they're for our call)
            // or BEFORE that call (meaning they might be for the nested call)
            FlowType flowType = instr.getFlowType();
            if (flowType.isCall()) {
                // Found a nested call - invalidate any argument registers
                // that were set before this call
                for (int j = 0; j < argRegSet.length; j++) {
                    if (argRegSet[j] && lastWriteAddr[j] != null) {
                        if (lastWriteAddr[j].compareTo(instr.getAddress()) <= 0) {
                            // This arg was set at or before the nested call
                            // It's probably for the nested call, not our call
                            argRegSet[j] = false;
                        }
                    }
                }
                // Stop looking further back
                break;
            }
        }

        // Determine the highest argument register set
        for (int i = 0; i < argRegSet.length; i++) {
            if (argRegSet[i]) {
                maxArgUsed = i;
            }
        }

        return maxArgUsed;
    }

    /**
     * Phase 5: Detect and type function pointer tables
     */
    private void typeFunctionPointerTables(Program program, TaskMonitor monitor) throws CancelledException {
        DataTypeManager dtMgr = program.getDataTypeManager();
        Memory memory = program.getMemory();

        // Look for contiguous arrays of pointers in data sections
        int pointerSize = program.getDefaultPointerSize();
        int minTableSize = 3;  // Minimum 3 entries to be considered a table
        int maxTableSize = 100;  // Maximum table size to check

        int txId = program.startTransaction("Type Function Pointer Tables");
        try {
            // Iterate through all memory blocks that are initialized and not executable
            for (var block : memory.getBlocks()) {
                monitor.checkCancelled();

                if (!block.isInitialized() || block.isExecute()) {
                    continue;  // Skip uninitialized or executable blocks
                }

                Address addr = block.getStart();
                Address endAddr = block.getEnd();

                while (addr != null && addr.compareTo(endAddr) < 0) {
                    monitor.checkCancelled();

                    // Try to detect a function pointer table starting at this address
                    int tableSize = detectFunctionPointerTable(program, addr, maxTableSize);

                    if (tableSize >= minTableSize) {
                        // Found a table, type it
                        boolean success = typeFunctionPointerTableEntries(program, addr, tableSize, dtMgr);

                        if (success) {
                            structFieldsTyped += tableSize;

                            if (verboseLogging) {
                                Msg.debug(this, String.format("Typed function pointer table at %s with %d entries",
                                    addr, tableSize));
                            }
                        }

                        // Skip past this table
                        addr = addr.add(tableSize * pointerSize);
                    } else {
                        // Move to next potential table location
                        addr = addr.add(pointerSize);
                    }

                    // Limit the number of tables we process
                    if (structFieldsTyped >= maxSyntheticTypes) {
                        Msg.info(this, "Reached maximum synthetic types limit");
                        break;
                    }
                }

                if (structFieldsTyped >= maxSyntheticTypes) {
                    break;
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }

        Msg.info(this, String.format("Table/Vector Typing: Typed %d function pointer table entries",
            structFieldsTyped));
    }

    /**
     * Detect if there's a function pointer table starting at the given address.
     * Returns the number of consecutive function pointers found (0 if not a table).
     */
    private int detectFunctionPointerTable(Program program, Address addr, int maxSize) {
        Memory memory = program.getMemory();
        FunctionManager funcMgr = program.getFunctionManager();
        int pointerSize = program.getDefaultPointerSize();

        int count = 0;
        Address current = addr;

        for (int i = 0; i < maxSize; i++) {
            try {
                // Read pointer value
                long ptrValue;
                if (pointerSize == 4) {
                    ptrValue = memory.getInt(current) & 0xFFFFFFFFL;
                } else {
                    ptrValue = memory.getLong(current);
                }

                // Check if this points to a valid function
                Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptrValue);

                if (targetAddr == null || !memory.contains(targetAddr)) {
                    break;  // Invalid pointer
                }

                Function func = funcMgr.getFunctionAt(targetAddr);
                if (func == null) {
                    // Not a function pointer, but could be null terminator
                    if (ptrValue == 0 && count > 0) {
                        // Null-terminated table
                        break;
                    }
                    break;
                }

                count++;
                current = current.add(pointerSize);

            } catch (Exception e) {
                break;  // Error reading memory
            }
        }

        return count;
    }

    /**
     * Type the entries of a function pointer table
     */
    private boolean typeFunctionPointerTableEntries(Program program, Address tableAddr, int size,
            DataTypeManager dtMgr) {

        Listing listing = program.getListing();
        int pointerSize = program.getDefaultPointerSize();

        try {
            // Create a function pointer data type
            FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType("fp_table_entry");
            PointerDataType funcPtr = new PointerDataType(funcDef, dtMgr);

            // Apply the type to each entry
            Address current = tableAddr;
            for (int i = 0; i < size; i++) {
                // Clear any existing data
                Data existingData = listing.getDataAt(current);
                if (existingData != null) {
                    listing.clearCodeUnits(current, current.add(pointerSize - 1), false);
                }

                // Create the function pointer data
                listing.createData(current, funcPtr, pointerSize);

                current = current.add(pointerSize);
            }

            return true;

        } catch (Exception e) {
            if (verboseLogging) {
                Msg.warn(this, "Failed to type function pointer table at " + tableAddr, e);
            }
            return false;
        }
    }

    /**
     * Report final results
     */
    private void reportResults(long elapsedMs) {
        Msg.info(this, "=== MIPS Driver Analyzer Results ===");
        Msg.info(this, String.format("  Execution time: %.2f seconds", elapsedMs / 1000.0));
        Msg.info(this, String.format("  Indirect call sites scanned: %d jalr, %d jr",
            jalrSitesScanned, jrSitesScanned));
        Msg.info(this, String.format("  Return-pointer functions typed: %d", returnPointerFunctionsTyped));
        Msg.info(this, String.format("  Trampolines detected: %d", trampolinesDetected));
        Msg.info(this, String.format("  Functions with parameters expanded: %d", functionsParamsExpanded));
        Msg.info(this, String.format("  Functions with parameters collapsed: %d", functionsParamsCollapsed));
        Msg.info(this, String.format("  Function pointer table entries typed: %d", structFieldsTyped));

        // Report detailed findings if verbose logging is enabled
        if (verboseLogging && !findings.isEmpty()) {
            Msg.info(this, "");
            Msg.info(this, "=== Detailed Findings ===");

            // Group findings by category
            Map<String, List<AnalysisFinding>> byCategory = new HashMap<>();
            for (AnalysisFinding finding : findings) {
                byCategory.computeIfAbsent(finding.category, k -> new ArrayList<>()).add(finding);
            }

            // Report each category
            for (Map.Entry<String, List<AnalysisFinding>> entry : byCategory.entrySet()) {
                Msg.info(this, String.format("  %s (%d findings):", entry.getKey(), entry.getValue().size()));
                for (AnalysisFinding finding : entry.getValue()) {
                    Msg.info(this, "    " + finding.toString());
                }
            }
        }

        Msg.info(this, "====================================");
    }
}

