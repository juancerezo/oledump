def my_repr(stringArg):
    stringRepr = repr(stringArg)
    if "'" + stringArg + "'" != stringRepr:
        return stringRepr
    else:
        return stringArg
