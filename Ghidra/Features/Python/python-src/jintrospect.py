## ###
#  IP: LGPL 2.1
##
"""Extend introspect.py for Java based Jython classes."""

from introspect import *
import string
import __builtin__
import java    # needed for java.lang.Class
import org     # for org.python.core
import ghidra  # for PythonCodeCompletionFactory

__author__ = "Don Coleman <dcoleman@chariotsolutions.com>"

#def getAutoCompleteList(command='', locals=None, includeMagic=1,
#                        includeSingle=1, includeDouble=1):
#    """Return list of auto-completion options for command.
#    
#    The list of options will be based on the locals namespace."""
#    attributes = []
#    # Get the proper chunk of code from the command.
#    root = getRoot(command, terminator='.')
#    try:
#        if locals is not None:
#            object = eval(root, locals)
#        else:
#            object = eval(root)
#    except:
#        #print "could not eval(", root, "):", sys.exc_info()[0]
#        return attributes
#    
#    if ispython(object):
#        # use existing code
#        attributes = getAttributeNames(object, includeMagic, includeSingle,
#                                       includeDouble)
#    else:
#        methods = methodsOf(object.__class__)
#        attributes = [eachMethod.__name__ for eachMethod in methods]
#    
#    return attributes
#
#def methodsOf(clazz):
#    """Return a list of all the methods in a class"""
#    classMembers = vars(clazz).values()
#    methods = [eachMember for eachMember in classMembers
#               if callable(eachMember)]
#    for eachBase in clazz.__bases__:
#        methods.extend(methodsOf(eachBase))
#    return methods

def getCallTipJava(command='', locals=None):
    """For a command, return a tuple of object name, argspec, tip text.
    
    The call tip information will be based on the locals namespace."""
    
    calltip = ('', '', '')  # object name, argspec, tip text.
    
    # Get the proper chunk of code from the command.
    (root, filter) = getRootAndFilter(command, terminator='(')
    #java.lang.System.out.println("root=" + root)
    
    try:
        if locals is not None:
            object = eval(root, locals)
        else:
            object = eval(root)
    except:
        #java.lang.System.err.println("could not eval(" + root + "):" +
        #                             str(sys.exc_info()[0]))
        return calltip
    
    if ispython(object):
        # Patrick's code handles Python code
        # TODO fix in future because getCallTip runs eval() again
        #java.lang.System.out.println("is a Python object")
        calltip = getCallTip(command, locals)
    
    if not calltip[1] and not calltip[2]:
        # either it's a pure Java object, or we didn't get much from Python's
        #  getCallTip
        name = ''
        try:
            name = object.__name__
        except AttributeError:
            pass
        
        tipList = []
        argspec = '' # not using argspec for Java
        
    #    if inspect.isbuiltin(object):
    #        # inspect.isbuiltin() fails for Jython
    #        # Can we get the argspec for Jython builtins?  We can't in Python.
    #        # YES!
    #        print "is a builtin"
    #        pass
    #    elif inspect.isclass(object):
        if inspect.isclass(object):
            # get the constructor(s)
            # TODO consider getting modifiers since Jython can access
            #  private methods
            #java.lang.System.out.println("is a class")
            try:
                # this will likely fail for pure Python classes
                constructors = object.getConstructors()
                for constructor in constructors:
                    paramList = []
                    paramTypes = constructor.getParameterTypes()
                    # paramTypes is an array of classes; we need Strings
                    # TODO consider list comprehension
                    for param in paramTypes:
                        # TODO translate [B to byte[], C to char[], etc.
                        paramList.append(param.__name__)
                    paramString = string.join(paramList, ', ')
                    tip = "%s(%s)" % (constructor.name, paramString)
                    tipList.append(tip)
                if len(constructors) == 1:
                    plural = ""
                else:
                    plural = "s"
                name = "Constructor" + plural + " for " + name + ":"
            except:
                pass
#                if callable(object):
#                    # some Python types are function names as well, like
#                    # type() and file()
#                    argspec = str(object.__call__)
#                    # these don't seem to be very accurate
#                    if hasattr(object.__call__, "maxargs"):
#                        tipList.append("maxargs?: " +
#                                       str(object.__call__.maxargs))
#                    if hasattr(object.__call__, "minargs"):
#                        tipList.append("minargs?: " +
#                                       str(object.__call__.minargs))
    #    elif inspect.ismethod(object):
        elif inspect.isroutine(object):
            #java.lang.System.out.println("is a routine")
    #        method = object
    #        object = method.im_class
    #        
    #        # Java allows overloading so we may have more than one method
    #        methodArray = object.getMethods()
    #        
    #        for eachMethod in methodArray:
    #            if eachMethod.name == method.__name__:
    #                paramList = []
    #                for eachParam in eachMethod.parameterTypes:
    #                    paramList.append(eachParam.__name__)
    #                
    #                    paramString = string.join(paramList, ', ')
    #                    
    #                    # create a Python style string a la PyCrust
    #                    # we're showing the parameter type rather than the
    #                    #  parameter name, since that's all we can get
    #                    # we need to show multiple methods for overloading
    #                    # TODO improve message format
    #                    # do we want to show the method visibility?
    #                    # how about exceptions?
    #                    # note: name, return type and exceptions same for
    #                    #  EVERY overloaded method
    #                    
    #                    
    #                    tip = "%s(%s) -> %s" % (eachMethod.name, paramString,
    #                                            eachMethod.returnType)
    #                    tipList.append(tip)
            if hasattr(object, "argslist"):
                for args in object.argslist:
                    if args is not None:
                        # for now
                        tipList.append(str(args.data))
#            elif callable(object):
#                argspec = str(object.__call__)
#                # these don't seem to be very accurate
#                if hasattr(object.__call__, "maxargs"):
#                    tipList.append("maxargs?: " + str(object.__call__.maxargs))
#                if hasattr(object.__call__, "minargs"):
#                    tipList.append("minargs?: " + str(object.__call__.minargs))
                    
    #    elif inspect.isfunction(object):
    #        print "is function"
    
        if (len(tipList) == 0):
            if hasattr(object, "__name__") and \
                hasattr(__builtin__, object.__name__):
                # try to get arguments for any other "old-style" builtin
                # functions (see __builtin__.java, classDictInit() method)
                methods = \
                java.lang.Class.getMethods(org.python.core.__builtin__)
                for method in methods:
                    if method.name == object.__name__:
                        tipList.append(str(method))
                argspec = "a built-in Python function"
            else:
                # last-ditch:  try possible __call__ methods of new-style
                # objects
                for possible_call_method in \
                ghidra.python.PythonCodeCompletionFactory.getCallMethods(object):
                    signature = str(possible_call_method)
                    # clean up the method signature a bit, so it looks sane
                    signature = \
                    signature.replace("$1exposed_", ".").replace(".__call__", "")
                    tipList.append(signature)
        
        calltip = (name, argspec, string.join(tipList, "\n"))
    return calltip

def ispython(object):
    """
    Figure out if this is Python code or Java code..
    """
    pyclass = 0
    pycode = 0
    pyinstance = 0
    
    if inspect.isclass(object):
        try:
            object.__doc__
            pyclass = 1
        except AttributeError:
            pyclass = 0
    elif inspect.ismethod(object):
        try:
            # changed for Jython 2.2a1
            #object.__dict__
            object.__str__
            pycode = 1
        except AttributeError:
            pycode = 0
    else: # I guess an instance of an object falls here
        try:
            # changed for Jython 2.2a1
            #object.__dict__
            object.__str__
            pyinstance = 1
        except AttributeError:
            pyinstance = 0
    
    return pyclass | pycode | pyinstance
