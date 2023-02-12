using System;

namespace Bulwark.Auth.Guard.Exceptions;
public class BulwarkAccountException : Exception
{
    public BulwarkAccountException(string message) :
        base(message)
    { }

    public BulwarkAccountException(string message, Exception inner) :
        base(message, inner)
    {

    }
}


