## ###
#  IP: LGPL 2.1
##
"""
Provides a variety of introspective-type support functions for
things like call tips and command auto completion.

NOTE: this file is a modification of Patrick O'Brien's version 1.62
"""

from __future__ import nested_scopes

import cStringIO
import inspect
import sys
import tokenize
import types
import __main__
from ghidra.python import PythonCodeCompletionFactory
import java    # needed for java.lang.Class

try:
    True
except NameError:
    True = 1==1
    False = 1==0

#from java.lang.System.out import println
    
def getAutoCompleteList(command='', locals=None, includeMagic=1,
                        includeSingle=1, includeDouble=1):
    """Return list of auto-completion tuples for command.
    
    First entry is the possible completions, and second entry is the
    of actual string that should be added to do the completion.
    
    The list of options will be based on the locals namespace."""
    attributes = []
    object = None
    # Get the proper chunk of code from the command.
    #root = getRoot(command, terminator='.')
    # and get the part of the completion we should filter on
    (root, filter) = getRootAndFilter(command, terminator='.')
    if root:
        jump_past_period = 1
    else:
        jump_past_period = 0

    #println("root='" + root + "'")
    #println("filter='" + filter + "'")
    
    if not root:
        # top-level?
        attributes = locals
    else:
        try:
            if locals is not None:
                object = eval(root, locals)
            else:
                object = eval(root)
        except:
            #print "could not eval(", root, "):", sys.exc_info()[0]
            pass
        else:
            attributes = getAttributeNames(object, includeMagic,
                                           includeSingle, includeDouble)
    completion_list = []
    for attribute in attributes:
        if attribute.lower().startswith(filter.lower()):
            try:
                if object is not None:
                    pyObj = getattr(object, attribute)
                else:
                    pyObj = locals[attribute]
                completion_list.append(PythonCodeCompletionFactory.
                                       newCodeCompletion(attribute,
                                                         attribute[len(filter):],
                                                         pyObj))
            except:
                # hmm, problem evaluating?  Examples of this include
                # inner classes, e.g. access$0, which aren't valid Python
                # anyway
                pass
    completion_list.sort(compare_completions)
    return completion_list

def compare_completions(comp1, comp2):
    return cmp(comp1.description, comp2.description)
                       
def getAttributeNames(object, includeMagic=1, includeSingle=1,
                      includeDouble=1):
    """Return list of unique attributes, including inherited, for object."""
    attributes = []
    dict = {}
    if not hasattrAlwaysReturnsTrue(object):
        # Add some attributes that don't always get picked up.  If
        # they don't apply, they'll get filtered out at the end
        attributes += ['__bases__', '__class__', '__dict__', '__name__',
                       'func_closure', 'func_code', 'func_defaults',
                       'func_dict', 'func_doc', 'func_globals', 'func_name']
    if includeMagic:
        try: attributes += object._getAttributeNames()
        except: pass
    # Get all attribute names.
    attrdict = getAllAttributeNames(object)
    for attrlist in attrdict.values():
        attributes += attrlist
    # Remove duplicates from the attribute list.
    for item in attributes:
        dict[item] = None
    attributes = dict.keys()
    attributes.sort(lambda x, y: cmp(x.upper(), y.upper()))
    if not includeSingle:
        attributes = filter(lambda item: item[0]!='_' \
                            or item[1]=='_', attributes)
    if not includeDouble:
        attributes = filter(lambda item: item[:2]!='__', attributes)
    #print "attributes currently", attributes
    # Make sure we haven't picked up any bogus attributes somehow.
    #attributes = [attribute for attribute in attributes \
    #              if hasattr(object, attribute)]
    retval = []
    for attribute in attributes:
        #print "checking", attribute
        try:
            if hasattr(object, attribute):
                retval += [attribute]
        except:
            # yes Virginia, hasattr() can fail in Jython 2.2 because trying
            # to get __doc__ on a builtin class results in NullPointerException
            pass
    return retval

def hasattrAlwaysReturnsTrue(object):
    return hasattr(object, 'bogu5_123_aTTri8ute')

def getAllAttributeNames(object):
    """Return dict of all attributes, including inherited, for an object.
    
    Recursively walk through a class and all base classes.
    """
    attrdict = {}  # (object, technique, count): [list of attributes]
    # !!!
    # Do Not use hasattr() as a test anywhere in this function,
    # because it is unreliable with the remote objects: xmlrpc, soap, etc.
    # They always return true for hasattr().
    # !!!
    try:
        # Yes, this can fail if object is an instance of a class with
        # __str__ (or __repr__) having a bug or raising an
        # exception. :-(
        key = str(object)
    except:
        key = 'anonymous'
    # Wake up sleepy object - a hack for ZODB objects in "ghost" state.
    try:
        wakeupcall = dir(object)
        del wakeupcall
    except:
        pass
    # Get attributes available through the normal convention
    try:
        attributes = dir(object)
        attrdict[(key, 'dir', len(attributes))] = attributes
    except:
        # sadly, this fails for PyReflectedFunctions
        pass
    # Get attributes rom the object's dictionary, if it has one.
    try:
        attributes = object.__dict__.keys()
        attributes.sort()
    except:  # Must catch all because object might have __getattr__.
        pass
    else:
        attrdict[(key, '__dict__', len(attributes))] = attributes
    # For a class instance, get the attributes for the class.
    try:
        klass = object.__class__
    except:  # Must catch all because object might have __getattr__.
        pass
    else:
        if klass is object:
            # Break a circular reference.  This happens with extension
            # classes.
            #print "breaking circular reference to self"
            pass
        # this extra check added for Jython 2.2.1 to break circular recursion
        elif klass is not java.lang.Class:
            # print "calling update from", object, "with", klass
            attrdict.update(getAllAttributeNames(klass))
    # Also get attributes from any and all parent classes.
    try:
        bases = object.__bases__
    except:  # Must catch all because object might have __getattr__.
        pass
    else:
        if isinstance(bases, types.TupleType):
            # needed for Jython 2.2?
            halt_type = type(types.TypeType)
            for base in bases:
                if type(base) is types.TypeType \
                    or type(base) is halt_type:
                    # Break a circular reference.  Happens in Python 2.2.
                    #print "breaking TypeType circular reference"
                    pass
                else:
                    # print "calling update (better not be 'type') with", base
                    attrdict.update(getAllAttributeNames(base))
    return attrdict

def getCallTip(command='', locals=None):
    """For a command, return a tuple of object name, argspec, tip text.
    
    The call tip information will be based on the locals namespace."""
    calltip = ('', '', '')  # object name, argspec, tip text.
    # Get the proper chunk of code from the command.
    root = getRoot(command, terminator='(')
    try:
        if locals is not None:
            object = eval(root, locals)
        else:
            object = eval(root)
    except:
        #print "could not eval(", root, "):", sys.exc_info()[0]
        return calltip
    name = ''
    object, dropSelf = getBaseObject(object)
    try:
        name = object.__name__
    except AttributeError:
        pass
    tip1 = ''
    argspec = ''
    if inspect.isbuiltin(object):
        # Builtin function don't have an argspec that we can get.
        pass
    elif inspect.isfunction(object):
        # tip1 is a string like: "getCallTip(command='', locals=None)"
        argspec = apply(inspect.formatargspec, inspect.getargspec(object))
        if dropSelf:
            # Thh first parameter to a method is a reference to an
            # instance, usually coded as "self", and is usually passed
            # automatically by Python; therefore we want to drop it.
            temp = argspec.split(',')
            if len(temp) == 1:  # No other arguments.
                argspec = '()'
            else:  # Drop the first argument.
                argspec = '(' + ','.join(temp[1:]).lstrip()
        tip1 = name + argspec
    doc = ''
    if callable(object):
        try:
            doc = inspect.getdoc(object)
        except:
            # Jython 2.2a1 could throw and exception with getdoc()
            pass
    if doc:
        # tip2 is the first separated line of the docstring, like:
        # "Return call tip text for a command."
        # tip3 is the rest of the docstring, like:
        # "The call tip information will be based on ... <snip>
        firstline = doc.split('\n')[0].lstrip()
        if tip1 == firstline:
            tip1 = ''
        else:
            tip1 += '\n\n'
        docpieces = doc.split('\n\n')
        tip2 = docpieces[0]
        tip3 = '\n\n'.join(docpieces[1:])
        tip = '%s%s\n\n%s' % (tip1, tip2, tip3)
    else:
        tip = tip1
    calltip = (name, argspec[1:-1], tip.strip())
    return calltip

def getRoot(command, terminator=None):
    """Return the rightmost root portion of an arbitrary Python command.
    
    Return only the root portion that can be eval()ed without side
    effect.  The command would normally terminate with a '(' or
    '.'.  The terminator and anything after the terminator will be
    dropped."""
    command = command.split('\n')[-1]
    if command.startswith(sys.ps2):
        command = command[len(sys.ps2):]
    command = command.lstrip()
    command = rtrimTerminus(command, terminator)
    tokens = getTokens(command)
    if not tokens:
        return ''
    if tokens[-1][0] is tokenize.ENDMARKER:
        # Remove the end marker.
        del tokens[-1]
    if not tokens:
        return ''
    if terminator == '.' and \
    (tokens[-1][1] <> '.' or tokens[-1][0] is not tokenize.OP):
        # Trap decimals in numbers, versus the dot operator
        return ''
    else:
        # Strip off the terminator.
        if terminator and command.endswith(terminator):
            size = 0 - len(terminator)
            command = command[:size]
    command = command.rstrip()
    tokens = getTokens(command)
    tokens.reverse()
    line = ''
    start = None
    prefix = ''
    laststring = '.'
    emptyTypes = ('[]', '()', '{}')
    for token in tokens:
        tokentype = token[0]
        tokenstring = token[1]
        line = token[4]
        if tokentype is tokenize.ENDMARKER:
            continue
        if tokentype in (tokenize.NAME, tokenize.STRING, tokenize.NUMBER) \
        and laststring != '.':
            # We've reached something that's not part of the root.
            if prefix and line[token[3][1]] != ' ':
                # If it doesn't have a space after it, remove the prefix.
                prefix = ''
            break
        if tokentype in (tokenize.NAME, tokenize.STRING, tokenize.NUMBER) \
        or (tokentype is tokenize.OP and tokenstring == '.'):
            if prefix:
                # The prefix isn't valid because it comes after a dot.
                prefix = ''
                break
            else:
                # start represents the last known good point in the line
                start = token[2][1]
        elif len(tokenstring) == 1 and tokenstring in ('[({])}'):
            # Remember, we're working backwards.
            # So prefix += tokenstring would be wrong.
            if prefix in emptyTypes and tokenstring in ('[({'):
                # We've already got an empty type identified so now we
                # are in a nested situation and we can break out with
                # what we've got
                break
            else:
                prefix = tokenstring = prefix
        else:
            # We've reached something that's not part of the root
            break
        laststring= tokenstring
    if start is None:
        start = len(line)
    root = line[start:]
    if prefix in emptyTypes:
        # Empty types are safe to be eval()'d and introspected.
        root = prefix + root
    return root

def getRootAndFilter(command, terminator=None):
    """Return the rightmost root portion of an arbitrary Python command.
    Also returns the filter, which is the fragment after the root and
    terminator.
    
    Return only the root portion that can be eval()ed without side
    effect.  The command would normally terminate with a '(' or
    '.'.  The terminator and anything after the terminator will be
    dropped."""
    command = command.split('\n')[-1]
    if command.startswith(sys.ps2):
        command = command[len(sys.ps2):]
    command = command.lstrip()
    tokens = getTokens(command)
    if not tokens:
        return ('', '')
    tokens.reverse()
    root = ""
    filter = ""
    terminator_seen = False
    # initialize matching bracket/paren sets
    op_mate = {'}': '{',
               ']': '[',
               ')': '('}
    op_stack = []
    while len(tokens) > 0:
        # work backwards through the tokens, starting at the end of the string
        token = tokens[0]
        del tokens[0]
        tokentype = token[0]
        tokenstring = token[1]
        line = token[4]
        if tokentype is tokenize.ENDMARKER:
            
            #println("Hit end marker; continuing")
            
            continue
        if not terminator_seen:
            if not filter and tokentype in (tokenize.NAME, tokenize.STRING):
                # okay, we think we've found our filter string
                filter = tokenstring
                
                #println("hit filter string '" + filter + "'")
                
            elif tokenstring == terminator:
                # hooray, our terminator!
                terminator_seen = True
            else:
                # either we found another token before our already-set
                # filter string, or we just found a bad token
                
                #println("No valid tokens found after terminator (at '" +
                #        tokenstring + "'")
                
                break
        else:
            # we've seen the terminator -- continue adding valid tokens
            # until we hit a token that stops us
            if tokentype in (tokenize.NAME, tokenize.STRING, tokenize.NUMBER):
                root = tokenstring + root
                
                #println("Added to root: '" + root + "'")
            
            elif tokentype is tokenize.OP:
                if tokenstring in op_mate.keys():
                    # found a closing bracket/paren
                    op_stack.append(tokenstring)
                elif tokenstring in op_mate.values():
                    if len(op_stack) < 1 or \
                        tokenstring != op_mate[op_stack.pop()]:
                        # uh-oh, non-matching brackets/parens!
                        break
                elif len(op_stack) > 0:
                    # weird tokens are okay inside brackets/parens
                    pass
                elif tokenstring == '.':
                    # dots are okay too!
                    pass
                else:
                    break
                
                root = tokenstring + root
                
                #println("Added to root: '" + root + "'")
            else:
                # hit a terminating token
                break
    return (root, filter)

def getTokens(command):
    """Return list of token tuples for command."""
    command = str(command)  # In case the command is unicode, which fails.
    f = cStringIO.StringIO(command)
    # tokens is a list of token tuples, each looking like:
    # (type, string, (srow, scol), (erow, ecol), line)
    tokens = []
    # Can't use list comprehension:
    #   tokens = [token for token in tokenize.generate_tokens(f.readline)]
    # because of need to append as much as possible before TokenError.
    try:
        # This works with Python 2.1.3 (with nested_scopes)
        def eater(*args):
            tokens.append(args)
        tokenize.tokenize_loop(f.readline, eater)
    except tokenize.TokenError:
        # This is due to a premature EOF, which we expect since we are
        # feeding in fragments of Python code
        pass
    return tokens

def rtrimTerminus(command, terminator=None):
    """Return command minus anything that follows the final terminator."""
    if terminator:
        pieces = command.split(terminator)
        if len(pieces) > 1:
            command = terminator.join(pieces[:-1]) + terminator
    return command

def getBaseObject(object):
    """Return base object and dropSelf indicator for an object."""
    if inspect.isbuiltin(object):
        # Builtin function don't have an argspec that we can get.
        dropSelf = 0
    elif inspect.ismethod(object):
        # Get the function from the object otherwise
        # inspect.getargspec() complains that the object isn't a
        # Python funciton.
        try:
            if object.im_self is None:
                # This is an unbound method so we do not drop self
                # from the argpec, sinc ean instance must be passed
                # as the first arg.
                dropSelf = 0
            else:
                dropSelf = 1
            object = object.im_func
        except AttributeError:
            dropSelf = 0
    elif inspect.isclass(object):
        # Get the __init__ method function for the class
        constructor = getConstructor(object)
        if constructor is not None:
            object = constructor
            dropSelf = 1
        else:
            dropSelf = 0
    elif callable(object):
        # Get the __call__ method instead
        try:
            call_method = object.__call__.im_func
            if call_method.__name__ == '__call__':
                # unbound jython method end up here, example: string.index(
                dropSelf = 0
            else:
                object = call_method
                dropSelf = 1
        except AttributeError:
            # unbound python methods end up here
            dropSelf = 0
    else:
        dropSelf = 0
    return object, dropSelf

def getConstructor(object):
    """Return constructor for class object, or None if there isn't one."""
    try:
        return object.__init__.im_func
    except AttributeError:
        for base in object.__bases__:
            constructor = getConstructor(base)
            if constructor is not None:
                return constructor
    return None
