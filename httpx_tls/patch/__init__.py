from ._async import patch_async
from ._base import Patch


def patch():
    patch_async()


def unpatch_all():
    Patch.unpatch_all()

