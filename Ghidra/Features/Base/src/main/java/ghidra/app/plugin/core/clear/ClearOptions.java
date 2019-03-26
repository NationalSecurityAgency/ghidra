/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.clear;

import ghidra.program.model.symbol.SourceType;

import java.util.HashSet;
import java.util.Set;

public class ClearOptions {

    private boolean code;
    private boolean symbols;
    private boolean comments;
    private boolean properties;
    private boolean functions;
    private boolean registers;
    private boolean equates;
    private boolean userReferences;
    private boolean analysisReferences;
    private boolean importReferences;
    private boolean defaultReferences;
    private boolean bookmarks;

	/**
	 * Default constructor that will clear everything!
	 */
	public ClearOptions() {
		this(true);  
	}

	public ClearOptions( boolean defaultClearValue ) {
	    this(defaultClearValue, defaultClearValue, defaultClearValue, defaultClearValue, 
	        defaultClearValue, defaultClearValue, defaultClearValue, defaultClearValue, 
	        defaultClearValue, defaultClearValue, defaultClearValue, defaultClearValue);
	}
	
    private ClearOptions(boolean code,
                		boolean symbols,
                		boolean comments,
                		boolean properties,
                		boolean functions,
                		boolean registers,
                		boolean equates,
                		boolean userReferences,
                		boolean analysisReferences,
                		boolean importReferences,
                		boolean defaultReferences,
                		boolean bookmarks) {
        this.code = code;
        this.symbols = symbols;
        this.comments = comments;
        this.properties = properties;
        this.functions = functions;
        this.registers = registers;
        this.equates = equates;
        this.userReferences = userReferences;
        this.analysisReferences = analysisReferences;
        this.importReferences = importReferences;
        this.defaultReferences = defaultReferences;
        this.bookmarks = bookmarks;
    }

    public void setClearCode( boolean code ) {
        this.code = code;
    }

    public void setClearSymbols( boolean symbols ) {
        this.symbols = symbols;
    }

    public void setClearComments( boolean comments ) {
        this.comments = comments;
    }

    public void setClearProperties( boolean properties ) {
        this.properties = properties;
    }

    public void setClearFunctions( boolean functions ) {
        this.functions = functions;
    }

    public void setClearRegisters( boolean registers ) {
        this.registers = registers;
    }

    public void setClearEquates( boolean equates ) {
        this.equates = equates;
    }

    public void setClearUserReferences( boolean userReferences ) {
        this.userReferences = userReferences;
    }

    public void setClearAnalysisReferences( boolean analysisReferences ) {
        this.analysisReferences = analysisReferences;
    }

    public void setClearImportReferences( boolean importReferences ) {
        this.importReferences = importReferences;
    }

    public void setClearDefaultReferences( boolean defaultReferences ) {
        this.defaultReferences = defaultReferences;
    }

    public void setClearBookmarks( boolean bookmarks ) {
        this.bookmarks = bookmarks;
    }
    
    boolean clearCode() {
        return code;
    }
    boolean clearComments() {
        return comments;
    }
    boolean clearProperties() {
        return properties;
    }
    boolean clearSymbols() {
        return symbols;
    }
    boolean clearFunctions() {
        return functions;
    }
    boolean clearRegisters() {
        return registers;
    }
    boolean clearEquates() {
        return equates;
    }
    boolean clearUserReferences() {
        return userReferences;
    }
    boolean clearAnalysisReferences() {
        return analysisReferences;
    }
    boolean clearImportReferences() {
        return importReferences;
    }
    boolean clearDefaultReferences() {
        return defaultReferences;
    }
    boolean clearBookmarks() {
    	return bookmarks;
    }

    Set<SourceType> getReferenceSourceTypesToClear() {
        HashSet<SourceType> sourceTypesToClear = new HashSet<SourceType>();
        if (clearUserReferences()) {
            sourceTypesToClear.add(SourceType.USER_DEFINED);
        }
        if (clearDefaultReferences()) {
            sourceTypesToClear.add(SourceType.DEFAULT);
        }
        if (clearImportReferences()) {
            sourceTypesToClear.add(SourceType.IMPORTED);
        }
        if (clearAnalysisReferences()) {
            sourceTypesToClear.add(SourceType.ANALYSIS);
        }
        return sourceTypesToClear;
    }

    boolean clearAny() {
        return code || symbols || comments || properties || functions
                || registers || equates || userReferences || analysisReferences
                || importReferences || defaultReferences || bookmarks;
    }
}
