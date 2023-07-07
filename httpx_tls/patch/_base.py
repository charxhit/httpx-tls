import functools


class Patch:
    patch_for = None
    black_list = ['patch', 'patch_for']
    original_funcs = {}

    @classmethod
    def patch(cls):
        method_list = [func for func in dir(cls)
                       if callable(getattr(cls, func)) and
                       (not func.startswith("__") and func not in cls.black_list)]

        # IMPORTANT: Because cls.original_funcs is a mutable object, subclasses will reference the same object as the
        # base class if they don't specifically override it in their class definition. That means, a subclasses'
        # original_funcs attr might be the same as another ones, which will be disastrous when unpatching! This is
        # why, we skip all this drama and manually create a new object for this attribute when patching.
        cls.original_funcs = {}
        for method in method_list:
            target_function = getattr(cls.patch_for, method)
            cls.original_funcs[method] = target_function

            partial_function = functools.partialmethod(getattr(cls, method), target_function)
            functools.update_wrapper(partial_function, target_function)
            setattr(cls.patch_for, method, partial_function)
