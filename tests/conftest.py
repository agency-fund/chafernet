import os

from hypothesis import settings

settings.register_profile("ci", max_examples=1000)
settings.register_profile("thorough", max_examples=20000)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
