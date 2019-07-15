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
/*
 * Created on Jun 13, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.match;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

import java.util.ArrayList;

/**
 * 
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
/**
 * Match maintains information about a single match between two programs.
 * The match can consist of either bytes or code units.
 */
public class Match implements Comparable<Match>
{
	private Address thisBeginning;
	private Address otherBeginning;
	private ArrayList<Object> thisMatch;
	private ArrayList<Object> otherMatch;
	private int totalLength;
	
	/**
	 * @param thisBeginning The start Address of the match in the program
	 * from which the matches are being found.
	 * @param otherBeginning The start Address of the match in the program
	 * to which the matches are being found.
	 * @param bytes the bytes which make up this match.
	 * @param length the length of the bytes array.
	 */
	public Match( Address thisBeginning, Address otherBeginning, byte[] bytes, int length)	
	{	

		this.thisBeginning = thisBeginning;
		this.otherBeginning = otherBeginning;
		thisMatch = new ArrayList<Object>();
		otherMatch = thisMatch;
		for( int i=0; i< length; i++)
		{
			String str;
			if( bytes[i] < 0 ) 
				str = Long.toHexString( bytes[i] + 256);
			else
				str = Long.toHexString( bytes[i]);
			thisMatch.add(i, str);
			totalLength++;
		}
	}
	
	/**
	 * @param thisBeginning The start Address of the match in the program
	 * from which the matches are being found.
	 * @param otherBeginning The start Address of the match in the program
	 * to which the matches are being found.
	 * @param codeUnits The CodeUnits which make up the match in this
	 * Program.
	 * @param otherUnits The CodeUnits which make up this match in the 
	 * other program. Note, the code units need no match up byte for 
	 * byte.
	 * @param length The length of the CodeUnit arrays.
	 */
	public Match( Address thisBeginning, Address otherBeginning, CodeUnit[] codeUnits, CodeUnit[] otherUnits, int length)
	{
		this.thisBeginning = thisBeginning;
		this.otherBeginning = otherBeginning;
		thisMatch = new ArrayList<Object>();
		otherMatch = new ArrayList<Object>();
		for( int i=0; i< length; i++)
		{
			thisMatch.add(i, codeUnits[i] );//.getAddressString(true).toString() );
			otherMatch.add( i, otherUnits[i] );
			totalLength += codeUnits[i].getLength();
		}

	}
	
	/**
	 * @param b Continue the match by adding the additional byte b.
	 */
	public void continueMatch( byte b )
	{
		String str;
		if( b < 0 ) 
			str = Long.toHexString( b + 256);
		else
			str = Long.toHexString( b);
		thisMatch.add( str );
		totalLength++;	
	}
	
//	/**
//	 * @param index
//	 * @return
//	 */
//	/**
//	 * @param index
//	 * @return
//	 */
//	/**
//	 * @param index
//	 * @return
//	 */
//	/**
//	 * @param index Zero-based index into an internal list of objects
//	 * making up this match.
//	 * @return The address of the object at the specified index in 
//	 * the other program.
//	 */
//	private Address getAddressAt( int index )
//	{
//		Object o = thisMatch.get(index);
//		if( o instanceof CodeUnit )
//		{
//			CodeUnit cu = (CodeUnit) o;
//			return cu.getMinAddress();
//		}
//		return getOtherBeginning().add(index);
//	}
	
	
	/**
	 * @param cu The CodeUnit which extends the match in 'this' program.
	 * @param otherUnit The CodeUnit which extends the match in 'the other'
	 * program.
	 */
	public void continueMatch( CodeUnit cu , CodeUnit otherUnit)
	{
		thisMatch.add( cu );//.getMinAddress().toString() );
		otherMatch.add( otherUnit );
		totalLength += cu.getLength();		
	}
	
	/** @return The number of items that make up this match. */
	public int length()
	{
		return thisMatch.size();
	}
	
	/** @return The total number of bytes that make up this match. */
	public int totalLength()
	{
		return totalLength;
	}
	
	@Override
    public String toString()
	{
		String str =  otherBeginning.toString(true) + "\n";
		for( int i=0; i< thisMatch.size(); i++ )
		{
			str += thisMatch.get(i).toString() + " ";
		}
		return str;
	}
	
	/**
	 * @return The Address that starts the match in the other program.
	 */
	public Address getOtherBeginning()
	{
		return otherBeginning;
	}


	/**
	 * @return The Address that starts the match in this program.
	 */
	public Address getThisBeginning()
	{
		return thisBeginning;
	}
	
	
	/**
	 * @return array containing the objects that make up the match 
	 * in this program.
	 */
	public Object[] getBytes()
	{
		return thisMatch.toArray(new Object[0]);
	}
	
	/**
	 * @return array containing the objects that make up the match 
	 * in the other program.
	 */
	public Object[] getOtherBytes()
	{
		return otherMatch.toArray(new Object[0]);
	}
	
	public String printMatch()
	{
		String str;
		str = "1.00 " + length() + " " + length() 
			+ thisBeginning.toString(true) + " " + Long.toHexString(thisBeginning.getOffset()) 
			+ otherBeginning.toString(true)+ " " + Long.toHexString(otherBeginning.getOffset()) + "\n";
		return str;											
	}
	

	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(Match m) {
		int val = getThisBeginning().compareTo( m.getThisBeginning() );
		if( val != 0 )
			return val;
		val = getOtherBeginning().compareTo( m.getOtherBeginning() );
		if( val != 0 )
			return val;		
		return length() - m.length();
	}
	
	/**
	 * @param baseLength the minimum number of items which make up a match.
	 * There are different values for instruction and byte matches. This
	 * value should either be NaiveMatchPlugin.MATCH_LENGTH_FOR_INSTRUCTIONS
	 * or NaiveMatchPlugin.MATCH_LENGTH_FOR_BYTES which can be found by
	 * calling getMatchLengthForInstructions() or getMatchLengthForBytes().
	 * @return The Address at which a continuing byte or code unit would
	 * be expected to be found in the other program.
	 */
	public Address expectedAddressForNextMatch(int baseLength)
	{
		Object o  = thisMatch.get( length() - baseLength + 1 );
		if( o instanceof CodeUnit)
		{	
			CodeUnit cu = (CodeUnit)thisMatch.get( length() - baseLength +1 );
			return cu.getMinAddress();
		}
		return this.thisBeginning.add(totalLength() - baseLength + 1);		
	}

}



