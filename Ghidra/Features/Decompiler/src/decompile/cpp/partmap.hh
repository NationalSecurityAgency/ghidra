/* ###
 * IP: GHIDRA
 * NOTE: very generic partition container
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
/// \file partmap.hh
/// \brief The partmap<> template mapping a linear space to value objects
#ifndef __PARTMAP__
#define __PARTMAP__

#include <map>

/// \brief A map from a linear space to value objects
///
/// The partmap is a template class taking:
///   -  _linetype which represents an element in the linear space
///   -  _valuetype which are the objects that linear space maps to
///
/// Let R be the linear space with an ordering, and let { a_i } be a finite set
/// of points in R.
/// The a_i partition R into a finite number of disjoint sets
/// { x : x < a_0 },  { x : x>=a_0 && x < a_1 }, ...
///                   { x : x>=a_i && x < a_i+1 }, ...
///                   { x : x>=a_n }
///
/// A partmap maps elements of this partition to _valuetype objects
/// A _valuetype is then associated with any element x in R by
/// looking up the value associated with the partition element
/// containing x.
///
/// The map is defined by starting with a \e default value object that applies
/// to the whole linear space.  Then \e split points are introduced, one at a time,
/// in the linear space. At each split point, the associated value object is split
/// into two objects.  At any point the value object describing some part of the linear space
/// can be changed.
template<typename _linetype,typename _valuetype>
class partmap {
public:
  typedef std::map<_linetype,_valuetype> maptype;		///< Defining the map from split points to value objects
  typedef typename maptype::iterator iterator;			///< A partmap iterator is an iterator into the map
  typedef typename maptype::const_iterator const_iterator;	///< A constant iterator
private:
  maptype database;						///< Map from linear split points to the value objects
  _valuetype defaultvalue;					///< The value object \e before the first split point
public:
  _valuetype &getValue(const _linetype &pnt);			///< Get the value object at a point
  const _valuetype &getValue(const _linetype &pnt) const;	///< Get the value object at a point
  const _valuetype &bounds(const _linetype &pnt,_linetype &before,_linetype &after,int &valid) const;
  _valuetype &split(const _linetype &pnt);			///< Introduce a new split point
  const _valuetype &defaultValue(void) const { return defaultvalue; }	///< Get the default value object
  _valuetype &defaultValue(void) { return defaultvalue; }		///< Get the default value object
  _valuetype & clearRange(const _linetype &pnt1,const _linetype &pnt2);	///< Clear a range of split points
  const_iterator begin(void) const { return database.begin(); }		///< Beginning of split points
  const_iterator end(void) const { return database.end(); }		///< End of split points
  iterator begin(void) { return database.begin(); }			///< Beginning of split points
  iterator end(void) { return database.end(); }				///< End of split points
  const_iterator begin(const _linetype &pnt) const { return database.lower_bound(pnt); }	///< Get first split point after given point
  iterator begin(const _linetype &pnt) { return database.lower_bound(pnt); }	///< Get first split point after given point
  void clear(void) { database.clear(); }				///< Clear all split points
  bool empty(void) const { return database.empty(); }			///< Return \b true if there are no split points
};

/// Look up the first split point coming before the given point
/// and return the value object it maps to. If there is no earlier split point
/// return the default value.
/// \param pnt is the given point in the linear space
/// \return the corresponding value object
template<typename _linetype,typename _valuetype>
  _valuetype &partmap<_linetype,_valuetype>::
  getValue(const _linetype &pnt)
  
  {
    iterator iter;

    iter = database.upper_bound(pnt);
    if (iter == database.begin())
      return defaultvalue;
    --iter;
    return (*iter).second;
  }

/// Look up the first split point coming before the given point
/// and return the value object it maps to. If there is no earlier split point
/// return the default value.
/// \param pnt is the given point in the linear space
/// \return the corresponding value object
template<typename _linetype,typename _valuetype>
  const _valuetype &partmap<_linetype,_valuetype>::
  getValue(const _linetype &pnt) const
  
  {
    const_iterator iter;
    
    iter = database.upper_bound(pnt);
    if (iter == database.begin())
      return defaultvalue;
    --iter;
    return (*iter).second;
  }

/// Add (if not already present) a point to the linear partition.
/// \param pnt is the (new) point
/// \return the (possibly) new value object for the range starting at the point
template<typename _linetype,typename _valuetype>
  _valuetype &partmap<_linetype,_valuetype>::
  split(const _linetype &pnt)

  {
    iterator iter;
    
    iter = database.upper_bound(pnt);
    if (iter != database.begin()) {
      --iter;
      if ((*iter).first == pnt)	// point matches exactly
	return (*iter).second;	// Return old ref
      _valuetype &newref( database[pnt] ); // Create new ref at point
      newref = (*iter).second;	// Copy of original partition value
      return newref;
    }
    _valuetype &newref( database[pnt] ); // Create new ref at point
    newref = defaultvalue;	// Copy of defaultvalue
    return newref;
  }

/// Split points are introduced at the two boundary points of the given range,
/// and all split points in between are removed. The value object that was initially
/// present at the left-most boundary point becomes the value (as a copy) for the whole range.
/// \param pnt1 is the left-most boundary point of the range
/// \param pnt2 is the right-most boundary point
/// \return the value object assigned to the range
template<typename _linetype,typename _valuetype>
  _valuetype &partmap<_linetype,_valuetype>::
  clearRange(const _linetype &pnt1,const _linetype &pnt2)
  {
    split(pnt1);
    split(pnt2);
    iterator beg = begin(pnt1);
    iterator end = begin(pnt2);
    
    _valuetype &ref( (*beg).second );
    ++beg;
    database.erase(beg,end);
    return ref;
  }  

/// \brief Get the value object for a given point and return the range over which the value object applies
///
/// Pass back a \b before and \b after point defining the maximal range over which the value applies.
/// An additional validity code is passed back describing which of the bounding points apply:
///   - 0 if both bounds apply
///   - 1 if there is no lower bound
///   - 2 if there is no upper bound,
///   - 3 if there is neither a lower or upper bound
/// \param pnt is the given point around which to compute the range
/// \param before is a reference to the passed back lower bound
/// \param after is a reference to the passed back upper bound
/// \param valid is a reference to the passed back validity code
/// \return the corresponding value object
template<typename _linetype,typename _valuetype>
  const _valuetype &partmap<_linetype,_valuetype>::
  bounds(const _linetype &pnt,_linetype &before,_linetype &after,int &valid) const
  {
    if (database.empty()) {
      valid = 3;
      return defaultvalue;
    }
    const_iterator iter,enditer;
    
    enditer = database.upper_bound(pnt);
    if (enditer != database.begin()) {
      iter = enditer;
      --iter;
      before = (*iter).first;
      if (enditer == database.end())
	valid = 2;		// No upperbound
      else {
	after = (*enditer).first;
	valid = 0;		// Fully bounded
      }
      return (*iter).second;
    }
    valid = 1;			// No lowerbound
    after = (*enditer).first;
    return defaultvalue;
  }
#endif

#if 0

#include <iostream>
using namespace std;

int main(int argc,char **argv)

{
  partmap<int,unsigned int> data;

  data.defaultValue() = 0;
  data.split(5) = 5;
  data.split(2) = 2;
  data.split(3) = 4;
  data.split(3) = 3;

  cout << data.getValue(6) << endl;
  cout << data.getValue(8) << endl;
  cout << data.getValue(4) << endl;
  cout << data.getValue(1) << endl;
  
  partmap<int,unsigned int>::const_iterator iter;

  iter = data.begin(3);
  while(iter!=data.end()) {
    cout << (*iter).second << endl;
    ++iter;
  }
}
#endif

