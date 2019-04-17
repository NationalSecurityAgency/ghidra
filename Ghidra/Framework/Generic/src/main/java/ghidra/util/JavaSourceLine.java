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
package ghidra.util;

public class JavaSourceLine {

	private int lineNumber;
	private String lineText;
	private String originalText;
    private boolean isDeleted;
	
	public JavaSourceLine(String line, int lineNumber) {
		this.lineText = line;
		this.originalText = line;
		this.lineNumber = lineNumber;		
	}

	public int getLineNumber() {
		return lineNumber;
	}
	
	public void delete() {
		lineText = "";
		isDeleted = true;
	}
	
	public String getLeadingWhitespace() {
	    int length = lineText.length();
        if ( length == 0 ) {
	        return "";
	    }
	    
	    StringBuffer buffy = new StringBuffer();
	    for ( int i = 0; i < length; i++ ) {
	        char charAt = lineText.charAt( i );
	        if ( !Character.isWhitespace( charAt ) ) {
	            break;
	        }
	        buffy.append( charAt );
	    }
	    
	    return buffy.toString();
	}
	
	public boolean isDeleted() {
	    return isDeleted;
	}
	
	public String getText() {
		return lineText;
	}
	
	public void prepend( String text ) {
		lineText = text + lineText;
		isDeleted = false;
	}
	
	public void append( String text ) {
		lineText += text;
		isDeleted = false;
	}
	
	public void setText( String text ) {
		lineText = text;
		isDeleted = false;
	}
	
	public boolean hasChanges() {
	    return !originalText.equals( lineText );
	}
	
	@Override
	public String toString() {
		return lineText;
	}

    JavaSourceLine createOriginalClone() {
        return new JavaSourceLine( originalText, lineNumber );
    }

    public String getOriginalText() {
        return originalText;
    }
}
