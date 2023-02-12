using System;

namespace Bulwark.Auth.Guard.Exceptions;
public class BulwarkException : Exception
{
	public BulwarkException(string message) :
		base(message){ }

    public BulwarkException(string message, Exception inner) :
        base(message, inner)
    {

    }
}


