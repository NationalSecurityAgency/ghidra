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
package ghidra.feature.vt.api.stringable.deprecated;

import java.util.*;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.listing.Program;

public class MultipleLocalVariableStringable extends Stringable {

    public static final String SHORT_NAME = "MULTI_LOCAL";
    
    private static final String CUSTOM_DELIMITER = "\n";
    
    private List<Stringable> localVariableStringables = new ArrayList<Stringable>();    

    public MultipleLocalVariableStringable() {
        this( null );
    }
    
    public MultipleLocalVariableStringable( List<LocalVariableStringable> localVariableStringables ) {
        super( SHORT_NAME );
        if ( localVariableStringables == null ) {
            this.localVariableStringables = new ArrayList<Stringable>();
        }
        else {
            this.localVariableStringables = new ArrayList<Stringable>( localVariableStringables );
        }
    }

    @Override
    protected String doConvertToString( Program program ) {
        StringBuffer buffy = new StringBuffer();
        
        for ( Stringable stringable : localVariableStringables ) {
            buffy.append( Stringable.getString( stringable, program ) ).append( CUSTOM_DELIMITER );
        }
        return buffy.toString();
    }

    @Override
    protected void doRestoreFromString( String string, Program program ) {
        if ( string == null ) {
            return;
        }
        
        StringTokenizer tokenizer = new StringTokenizer( string, CUSTOM_DELIMITER );
        while ( tokenizer.hasMoreTokens() ) {
            String token = tokenizer.nextToken();            
            Stringable stringable = Stringable.getStringable( token, program );
            localVariableStringables.add( stringable );
        }
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = prime * ((localVariableStringables == null) ? 0 : localVariableStringables.hashCode());
        return result;
    }

    @Override
    public boolean equals( Object obj ) {
    		if (obj == null) {
			return false;
		}
    	
        if ( this == obj ) {
            return true;
        }
        if ( getClass() != obj.getClass() ) {
            return false;
        }
        
        MultipleLocalVariableStringable other = (MultipleLocalVariableStringable) obj;
        if ( localVariableStringables == null ) {
            if ( other.localVariableStringables != null ) {
                return false;
            }
        }
        else if ( !localVariableStringables.equals( other.localVariableStringables ) ) {
            return false;
        }
        return true;
    }

    @Override
    public String getDisplayString( ) {
        StringBuffer buffy = new StringBuffer();
        for ( Stringable stringable : localVariableStringables ) {
            buffy.append( stringable.getDisplayString( ) ).append( '\n' );
        }
        return buffy.toString();
    }
}
